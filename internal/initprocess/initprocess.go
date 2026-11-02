package initprocess

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	Severity string `json:"severity"`
	RuleID   string `json:"rule_id"`
	Detail   string `json:"detail"`
}

type ServiceResult struct {
	Name     string    `json:"name"`
	File     string    `json:"file"`
	HasInit  bool      `json:"has_init"`
	HasTty   bool      `json:"has_tty"`
	HasStdin bool      `json:"has_stdin"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices int `json:"total_services"`
	WithInit      int `json:"with_init"`
	WithTty       int `json:"with_tty"`
	WithStdin     int `json:"with_stdin"`
	WithIssues    int `json:"with_issues"`
	TotalFindings int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func Analyze(collected *collect.Collected) Report {
	var results []ServiceResult
	var totalSvcs, withInit, withTty, withStdin, withIssues, totalFindings int

	for i := range collected.ComposeFiles {
		cf := &collected.ComposeFiles[i]
		for _, svc := range cf.Services {
			totalSvcs++
			sr := ServiceResult{
				Name:     svc.Name,
				File:     cf.Path,
				HasInit:  svc.Init,
				HasTty:   svc.Tty,
				HasStdin: svc.StdinOpen,
			}
			if svc.Init {
				withInit++
			}
			if svc.Tty {
				withTty++
			}
			if svc.StdinOpen {
				withStdin++
			}

			findings := analyzeService(svc, cf)
			sr.Findings = findings
			if len(findings) > 0 {
				withIssues++
				totalFindings += len(findings)
			}
			results = append(results, sr)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return len(results[i].Findings) > len(results[j].Findings)
	})

	return Report{
		Services: results,
		Summary: Summary{
			TotalServices: totalSvcs,
			WithInit:      withInit,
			WithTty:       withTty,
			WithStdin:     withStdin,
			WithIssues:    withIssues,
			TotalFindings: totalFindings,
		},
	}
}

func analyzeService(svc compose.Service, cf *compose.File) []Finding {
	var findings []Finding

	if !svc.Init && isLongRunning(svc) {
		findings = append(findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "medium",
			RuleID:   "init_missing",
			Detail:   "long-running service without init: true; PID 1 may not reap zombie processes or handle signals correctly",
		})
	}

	if svc.Tty && svc.StdinOpen {
		findings = append(findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "medium",
			RuleID:   "init_interactive",
			Detail:   "service has tty: true and stdin_open: true, indicating interactive mode; not suitable for production",
		})
	}

	if svc.StopGracePeriod == "" && isLongRunning(svc) {
		findings = append(findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "low",
			RuleID:   "init_no_grace_period",
			Detail:   "no stop_grace_period set; defaults to 10s which may be too short for graceful shutdown",
		})
	}

	if svc.StopGracePeriod != "" && isShortGracePeriod(svc.StopGracePeriod) {
		findings = append(findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "low",
			RuleID:   "init_short_grace",
			Detail:   fmt.Sprintf("stop_grace_period is %s; may be too short for graceful shutdown", svc.StopGracePeriod),
		})
	}

	if svc.Privileged && !svc.Init {
		findings = append(findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "high",
			RuleID:   "init_privileged_no_init",
			Detail:   "privileged container without init: true; zombie processes could consume host resources",
		})
	}

	if svc.Tty && !svc.Init {
		findings = append(findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "low",
			RuleID:   "init_tty_no_init",
			Detail:   "service uses tty without init: true; signals may not propagate correctly",
		})
	}

	return findings
}

func isLongRunning(svc compose.Service) bool {
	if svc.Restart == "always" || svc.Restart == "unless-stopped" || svc.Restart == "on-failure" {
		return true
	}
	if len(svc.Ports) > 0 {
		return true
	}
	if svc.Healthcheck != nil && !svc.Healthcheck.Disable {
		return true
	}
	return false
}

func isShortGracePeriod(period string) bool {
	p := strings.TrimSpace(strings.ToLower(period))
	if p == "0" || p == "0s" || p == "1s" || p == "2s" || p == "3s" {
		return true
	}
	return false
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Init Process Configuration Audit\n")
	sb.WriteString(strings.Repeat("=", 62) + "\n\n")
	sb.WriteString(fmt.Sprintf("  Total services:       %d\n", r.Summary.TotalServices))
	sb.WriteString(fmt.Sprintf("  With init: true:      %d\n", r.Summary.WithInit))
	sb.WriteString(fmt.Sprintf("  With tty:             %d\n", r.Summary.WithTty))
	sb.WriteString(fmt.Sprintf("  With stdin_open:      %d\n", r.Summary.WithStdin))
	sb.WriteString(fmt.Sprintf("  Services with issues: %d\n", r.Summary.WithIssues))
	sb.WriteString(fmt.Sprintf("  Total findings:       %d\n\n", r.Summary.TotalFindings))

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s (%s):\n", sr.Name, sr.File))
		for _, f := range sr.Findings {
			sb.WriteString(fmt.Sprintf("    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Detail))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
