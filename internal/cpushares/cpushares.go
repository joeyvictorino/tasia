package cpushares

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type ServiceResult struct {
	Service   string    `json:"service"`
	File      string    `json:"file"`
	CpuShares int       `json:"cpu_shares"`
	Findings  []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices     int `json:"total_services"`
	NoShares          int `json:"no_shares"`
	HighShares        int `json:"high_shares"`
	LowShares         int `json:"low_shares"`
	DefaultShares     int `json:"default_shares"`
	TotalFindings     int `json:"total_findings"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Service:   svc.Name,
		File:      file,
		CpuShares: svc.CpuShares,
	}

	if svc.CpuShares == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "cpu_shares_unset",
			Message: fmt.Sprintf("Service '%s' has no cpu_shares set; defaults to 1024 which gives equal scheduling weight", svc.Name),
		})
		return sr
	}

	if svc.CpuShares > 4096 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "cpu_shares_excessive",
			Message: fmt.Sprintf("Service '%s' has cpu_shares=%d (>4096); may starve other containers of CPU time", svc.Name, svc.CpuShares),
		})
	}

	if svc.CpuShares < 128 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cpu_shares_starved",
			Message: fmt.Sprintf("Service '%s' has cpu_shares=%d (<128); may be starved under contention", svc.Name, svc.CpuShares),
		})
	}

	if svc.CpuShares == 1024 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "cpu_shares_default",
			Message: fmt.Sprintf("Service '%s' explicitly sets cpu_shares=1024 (default value)", svc.Name),
		})
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "cpu_shares_unset":
				s.NoShares++
			case "cpu_shares_excessive":
				s.HighShares++
			case "cpu_shares_starved":
				s.LowShares++
			case "cpu_shares_default":
				s.DefaultShares++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CPU Shares Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Unset (default):   %d\n", r.Summary.NoShares)
	fmt.Fprintf(&b, "  Excessive (>4096): %d\n", r.Summary.HighShares)
	fmt.Fprintf(&b, "  Starved (<128):    %d\n\n", r.Summary.LowShares)
	for _, sr := range r.Services {
		shares := "default"
		if sr.CpuShares > 0 {
			shares = fmt.Sprintf("%d", sr.CpuShares)
		}
		fmt.Fprintf(&b, "  %-30s cpu_shares: %s\n", sr.Service, shares)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
