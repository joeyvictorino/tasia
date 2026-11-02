package pidsec

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
	NoInit        int `json:"no_init"`
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
	sr := ServiceResult{Service: svc.Name, File: file}

	if svc.PidsLimit == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "pidsec_no_pid_limit",
			Message: fmt.Sprintf("Service '%s' has no pids_limit; fork bombs can exhaust host PIDs", svc.Name),
		})
	} else if svc.PidsLimit > 4096 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "pidsec_high_pid_limit",
			Message: fmt.Sprintf("Service '%s' has pids_limit=%d (>4096); consider a lower limit", svc.Name, svc.PidsLimit),
		})
	}

	if !svc.Init {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "pidsec_no_init",
			Message: fmt.Sprintf("Service '%s' does not use init:true; zombie processes may accumulate", svc.Name),
		})
	}

	return sr
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "PID Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No pids_limit: %d\n", r.Summary.NoPidLimit)
	fmt.Fprintf(&b, "  High pids_limit: %d\n", r.Summary.HighPidLimit)
	fmt.Fprintf(&b, "  No init: %d\n\n", r.Summary.NoInit)
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

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, svc := range services {
		s.TotalFindings += len(svc.Findings)
		for _, f := range svc.Findings {
			switch f.Rule {
			case "pidsec_no_pid_limit":
				s.NoPidLimit++
			case "pidsec_high_pid_limit":
				s.HighPidLimit++
			case "pidsec_no_init":
				s.NoInit++
			}
		}
	}
	return s
}
