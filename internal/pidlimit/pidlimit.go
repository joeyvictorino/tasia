package pidlimit

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
	Service  string    `json:"service"`
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices int `json:"total_services"`
	TotalFindings int `json:"total_findings"`
	NoPidLimit    int `json:"no_pid_limit"`
	HighPidLimit  int `json:"high_pid_limit"`
	UnlimitedPid  int `json:"unlimited_pid"`
	LowPidLimit   int `json:"low_pid_limit"`
}

const (
	highThreshold = 32768
	lowThreshold  = 10
)

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
	sr := ServiceResult{Service: svc.Name, File: file}

	if svc.PidsLimit == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "pidlimit_missing",
			Message: fmt.Sprintf("Service '%s' has no pids_limit; vulnerable to fork bomb attacks", svc.Name),
		})
	} else if svc.PidsLimit == -1 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "pidlimit_unlimited",
			Message: fmt.Sprintf("Service '%s' has pids_limit: -1 (unlimited); vulnerable to fork bomb attacks", svc.Name),
		})
	} else if svc.PidsLimit > highThreshold {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "pidlimit_high",
			Message: fmt.Sprintf("Service '%s' has pids_limit: %d (>%d); consider lowering to reduce fork bomb risk", svc.Name, svc.PidsLimit, highThreshold),
		})
	} else if svc.PidsLimit > 0 && svc.PidsLimit < lowThreshold {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "pidlimit_low",
			Message: fmt.Sprintf("Service '%s' has pids_limit: %d (<%d); may be too restrictive for normal operation", svc.Name, svc.PidsLimit, lowThreshold),
		})
	}

	if svc.Privileged && svc.PidsLimit == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "pidlimit_privileged_no_limit",
			Message: fmt.Sprintf("Service '%s' is privileged with no PID limit; a fork bomb could impact the host", svc.Name),
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
			case "pidlimit_missing":
				s.NoPidLimit++
			case "pidlimit_high":
				s.HighPidLimit++
			case "pidlimit_unlimited":
				s.UnlimitedPid++
			case "pidlimit_low":
				s.LowPidLimit++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "PID Limit Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No PID limit:      %d\n", r.Summary.NoPidLimit)
	fmt.Fprintf(&b, "  Unlimited PID:     %d\n", r.Summary.UnlimitedPid)
	fmt.Fprintf(&b, "  High PID limit:    %d\n", r.Summary.HighPidLimit)
	fmt.Fprintf(&b, "  Low PID limit:     %d\n\n", r.Summary.LowPidLimit)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s\n", sr.Service)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		if len(sr.Findings) == 0 {
			fmt.Fprintf(&b, "    (no findings)\n")
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
