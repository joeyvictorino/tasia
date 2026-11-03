package ulimits

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service     string `json:"service"`
	File        string `json:"file"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	UlimitName  string `json:"ulimit_name,omitempty"`
	UlimitValue string `json:"ulimit_value,omitempty"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Name     string                        `json:"name"`
	File     string                        `json:"file"`
	Ulimits  map[string]compose.UlimitValue `json:"ulimits,omitempty"`
	Findings []Finding                     `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices        int `json:"total_services"`
	ServicesWithUlimits  int `json:"services_with_ulimits"`
	ServicesMissing      int `json:"services_missing_ulimits"`
	TotalFindings        int `json:"total_findings"`
	UnlimitedCount       int `json:"unlimited_count"`
	TooHighCount         int `json:"too_high_count"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var thresholds = map[string]int64{
	"nofile":  65536,
	"nproc":   4096,
}

var unlimitedDangerous = map[string]bool{
	"memlock": true,
	"core":    true,
	"nofile":  true,
	"nproc":   true,
}

func Analyze(collected *collect.Collected) Report {
	var services []ServiceResult
	for _, cf := range collected.ComposeFiles {
		for i := range cf.Services {
			sr := analyzeService(&cf.Services[i], cf.Path)
			services = append(services, sr)
		}
	}

	summary := Summary{TotalServices: len(services)}
	for _, s := range services {
		if len(s.Ulimits) > 0 {
			summary.ServicesWithUlimits++
		} else {
			summary.ServicesMissing++
		}
		summary.TotalFindings += len(s.Findings)
		for _, f := range s.Findings {
			switch f.RuleID {
			case "ulimit_unlimited":
				summary.UnlimitedCount++
			case "ulimit_too_high":
				summary.TooHighCount++
			}
		}
	}
	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:    svc.Name,
		File:    file,
		Ulimits: svc.Ulimits,
	}

	if len(svc.Ulimits) == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "ulimit_missing",
			Severity:    "low",
			Detail:      "No ulimits configured; container processes have no resource limits, risking denial-of-service via fork bombs or file descriptor exhaustion",
			Remediation: "Add ulimits section with at least nofile and nproc limits (e.g. nofile: 65536, nproc: 4096)",
		})
		return sr
	}

	for name, val := range svc.Ulimits {
		hard := val.Hard
		if hard == -1 || val.Soft == -1 {
			if unlimitedDangerous[name] {
				sr.Findings = append(sr.Findings, Finding{
					Service:     svc.Name,
					File:        file,
					RuleID:      "ulimit_unlimited",
					Severity:    "medium",
					UlimitName:  name,
					UlimitValue: "unlimited",
					Detail:      fmt.Sprintf("ulimit %s set to unlimited; no upper bound on resource consumption", name),
					Remediation: fmt.Sprintf("Set %s to a finite value appropriate for the workload", name),
				})
			}
			continue
		}

		if thresh, ok := thresholds[name]; ok {
			if hard > thresh {
				sr.Findings = append(sr.Findings, Finding{
					Service:     svc.Name,
					File:        file,
					RuleID:      "ulimit_too_high",
					Severity:    "medium",
					UlimitName:  name,
					UlimitValue: fmt.Sprintf("%d", hard),
					Detail:      fmt.Sprintf("ulimit %s hard limit %d exceeds recommended maximum %d", name, hard, thresh),
					Remediation: fmt.Sprintf("Reduce %s to %d or lower unless the workload specifically requires more", name, thresh),
				})
			}
		}
	}

	return sr
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Process Ulimit Audit (%d services, %d with ulimits, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.ServicesWithUlimits, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Missing ulimits:  %d services\n", r.Summary.ServicesMissing)
	fmt.Fprintf(&b, "  Unlimited values: %d\n", r.Summary.UnlimitedCount)
	fmt.Fprintf(&b, "  Too-high values:  %d\n\n", r.Summary.TooHighCount)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%s)\n", s.Name, s.File)
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s", f.Severity, f.Detail)
			if f.UlimitName != "" {
				fmt.Fprintf(&b, " (%s=%s)", f.UlimitName, f.UlimitValue)
			}
			b.WriteString("\n")
			fmt.Fprintf(&b, "           Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
	return b.String()
}
