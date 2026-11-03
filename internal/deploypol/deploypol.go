package deploypol

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
	Service        string    `json:"service"`
	File           string    `json:"file"`
	HasDeployPol   bool      `json:"has_deploy_policy"`
	RestartPolicy  string    `json:"restart_policy,omitempty"`
	MaxRetries     int       `json:"max_retries,omitempty"`
	Findings       []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	NoDeployPolicy   int `json:"no_deploy_policy"`
	UnlimitedRetries int `json:"unlimited_retries"`
	AlwaysRestart    int `json:"always_restart"`
	TotalFindings    int `json:"total_findings"`
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
		Service: svc.Name,
		File:    file,
	}

	dp := svc.DeployRestartPolicy
	if dp == nil {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "deploy_no_restart_policy",
			Message: fmt.Sprintf("service %q has no deploy restart_policy; default behavior may not match production needs", svc.Name),
		})
		return sr
	}

	sr.HasDeployPol = true
	sr.RestartPolicy = dp.Condition

	if dp.Condition == "any" && dp.MaxAttempts == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "deploy_unlimited_retries",
			Message: fmt.Sprintf("service %q has restart condition 'any' with no max_attempts; crash-looping services will restart indefinitely", svc.Name),
		})
	}

	if dp.MaxAttempts > 0 {
		sr.MaxRetries = dp.MaxAttempts
	}

	if dp.MaxAttempts > 100 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "deploy_excessive_retries",
			Message: fmt.Sprintf("service %q has max_attempts=%d; excessive retries can mask underlying failures", svc.Name, dp.MaxAttempts),
		})
	}

	if dp.Condition == "none" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "deploy_no_restart",
			Message: fmt.Sprintf("service %q has restart condition 'none'; service will not recover from crashes", svc.Name),
		})
	}

	if svc.Privileged && dp.Condition == "any" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "deploy_privileged_always_restart",
			Message: fmt.Sprintf("privileged service %q restarts on any failure; a compromised privileged container will persist", svc.Name),
		})
	}

	if dp.Delay != "" && isShortDelay(dp.Delay) && dp.Condition == "any" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "deploy_short_delay",
			Message: fmt.Sprintf("service %q has very short restart delay %s with condition 'any'; may cause resource exhaustion during rapid restarts", svc.Name, dp.Delay),
		})
	}

	return sr
}

func isShortDelay(delay string) bool {
	d := strings.ToLower(strings.TrimSpace(delay))
	if d == "0s" || d == "0" || d == "1s" || d == "2s" {
		return true
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		if !sr.HasDeployPol {
			s.NoDeployPolicy++
		}
		for _, f := range sr.Findings {
			switch f.Rule {
			case "deploy_unlimited_retries":
				s.UnlimitedRetries++
			case "deploy_privileged_always_restart":
				s.AlwaysRestart++
			}
		}
		s.TotalFindings += len(sr.Findings)
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Deploy Restart Policy Analysis: %s\n\n", r.Path)
	for _, sr := range r.Services {
		policy := "(no deploy restart policy)"
		if sr.HasDeployPol {
			policy = fmt.Sprintf("condition=%s", sr.RestartPolicy)
			if sr.MaxRetries > 0 {
				policy += fmt.Sprintf(" max_attempts=%d", sr.MaxRetries)
			}
		}
		fmt.Fprintf(&b, "  %s %s\n", sr.Service, policy)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s – %s\n", f.Level, f.Rule, f.Message)
		}
	}
	fmt.Fprintf(&b, "\n  Summary: %d services, %d no policy, %d unlimited retries, %d always-restart privileged, %d findings\n",
		r.Summary.TotalServices, r.Summary.NoDeployPolicy, r.Summary.UnlimitedRetries, r.Summary.AlwaysRestart, r.Summary.TotalFindings)
	return b.String()
}
