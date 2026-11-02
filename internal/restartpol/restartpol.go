package restartpol

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service     string `json:"service"`
	File        string `json:"file"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Policy      string `json:"policy,omitempty"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Name          string    `json:"name"`
	File          string    `json:"file"`
	RestartPolicy string    `json:"restart_policy,omitempty"`
	Findings      []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices       int `json:"total_services"`
	AlwaysRestart       int `json:"always_restart"`
	NoPolicy            int `json:"no_policy"`
	NoMaxAttempts       int `json:"no_max_attempts"`
	RapidRestart        int `json:"rapid_restart"`
	TotalFindings       int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
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
		for _, f := range s.Findings {
			summary.TotalFindings++
			switch f.RuleID {
			case "restart_always_agent":
				summary.AlwaysRestart++
			case "restart_missing":
				summary.NoPolicy++
			case "restart_no_limit":
				summary.NoMaxAttempts++
			case "restart_rapid":
				summary.RapidRestart++
			}
		}
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:          svc.Name,
		File:          file,
		RestartPolicy: svc.Restart,
	}

	if svc.Restart == "" && svc.DeployRestartPolicy == nil {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "restart_missing",
			Severity:    "low",
			Detail:      "No restart policy configured; container will not restart after a crash",
			Remediation: "Set restart: on-failure or use deploy.restart_policy with condition: on-failure and max_attempts",
		})
		return sr
	}

	if svc.Restart == "always" {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "restart_always_agent",
			Severity:    "medium",
			Policy:      "always",
			Detail:      "restart: always will continuously restart a crashing container, potentially amplifying attacks or resource exhaustion",
			Remediation: "Use restart: on-failure with max retries, or deploy.restart_policy with max_attempts to bound crash loops",
		})
	}

	if svc.Restart == "unless-stopped" {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "restart_always_agent",
			Severity:    "low",
			Policy:      "unless-stopped",
			Detail:      "restart: unless-stopped behaves like always except after manual stop; still allows unbounded crash loops",
			Remediation: "Consider restart: on-failure or deploy.restart_policy with max_attempts to bound restart behavior",
		})
	}

	if svc.DeployRestartPolicy != nil {
		rp := svc.DeployRestartPolicy
		sr.RestartPolicy = fmt.Sprintf("deploy(condition=%s)", rp.Condition)

		if rp.MaxAttempts == 0 {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "restart_no_limit",
				Severity:    "medium",
				Policy:      sr.RestartPolicy,
				Detail:      "deploy.restart_policy has no max_attempts; container can restart indefinitely",
				Remediation: "Set max_attempts (e.g. 5) in deploy.restart_policy to limit restart loops",
			})
		} else if rp.MaxAttempts > 10 {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "restart_no_limit",
				Severity:    "low",
				Policy:      sr.RestartPolicy,
				Detail:      fmt.Sprintf("deploy.restart_policy max_attempts=%d is very high; extended crash loops may mask failures", rp.MaxAttempts),
				Remediation: "Consider reducing max_attempts to 5 or fewer and investigating root causes of repeated restarts",
			})
		}

		if rp.Delay != "" {
			if isRapidDelay(rp.Delay) {
				sr.Findings = append(sr.Findings, Finding{
					Service:     svc.Name,
					File:        file,
					RuleID:      "restart_rapid",
					Severity:    "medium",
					Policy:      sr.RestartPolicy,
					Detail:      fmt.Sprintf("deploy.restart_policy delay=%s is very short; rapid restarts can amplify resource consumption", rp.Delay),
					Remediation: "Set delay to at least 5s to allow failing services time to release resources between restarts",
				})
			}
		}
	}

	return sr
}

func isRapidDelay(delay string) bool {
	d := strings.TrimSpace(delay)
	if strings.HasSuffix(d, "ms") {
		return true
	}
	if strings.HasSuffix(d, "s") {
		val := strings.TrimSuffix(d, "s")
		if n, err := strconv.Atoi(val); err == nil && n < 5 {
			return true
		}
	}
	if n, err := strconv.Atoi(d); err == nil && n < 5 {
		return true
	}
	return false
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Restart Policy Security Audit (%d services, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.TotalFindings)

	fmt.Fprintf(&b, "  Always-restart services: %d\n", r.Summary.AlwaysRestart)
	fmt.Fprintf(&b, "  Missing restart policy:  %d\n", r.Summary.NoPolicy)
	fmt.Fprintf(&b, "  No max_attempts limit:   %d\n", r.Summary.NoMaxAttempts)
	fmt.Fprintf(&b, "  Rapid restart delay:     %d\n\n", r.Summary.RapidRestart)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%s)\n", s.Name, s.File)
		if s.RestartPolicy != "" {
			fmt.Fprintf(&b, "    policy: %s\n", s.RestartPolicy)
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.RuleID, f.Detail)
			fmt.Fprintf(&b, "           Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
	return b.String()
}
