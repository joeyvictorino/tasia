package stopgrace

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
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Name     string    `json:"name"`
	File     string    `json:"file"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	SigkillSignal    int `json:"sigkill_signal"`
	ShortGrace       int `json:"short_grace"`
	LongGrace        int `json:"long_grace"`
	MissingGrace     int `json:"missing_grace"`
	TotalFindings    int `json:"total_findings"`
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
			case "stop_sigkill":
				summary.SigkillSignal++
			case "stop_grace_short":
				summary.ShortGrace++
			case "stop_grace_long":
				summary.LongGrace++
			case "stop_grace_missing":
				summary.MissingGrace++
			}
		}
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{Name: svc.Name, File: file}

	sig := strings.ToUpper(svc.StopSignal)
	if sig == "SIGKILL" || sig == "9" {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "stop_sigkill",
			Severity:    "high",
			Detail:      "stop_signal is SIGKILL; container cannot perform graceful shutdown or cleanup",
			Remediation: "Use SIGTERM (default) or SIGQUIT to allow the process to shut down cleanly",
		})
	}

	if svc.StopSignal != "" && svc.StopGracePeriod == "" {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "stop_grace_missing",
			Severity:    "low",
			Detail:      fmt.Sprintf("Custom stop_signal %s set without stop_grace_period; default 10s may not be enough", svc.StopSignal),
			Remediation: "Set stop_grace_period appropriate for your service's shutdown behavior",
		})
	}

	if svc.StopGracePeriod != "" {
		if isShortGrace(svc.StopGracePeriod) {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "stop_grace_short",
				Severity:    "medium",
				Detail:      fmt.Sprintf("stop_grace_period=%s is very short; service may be killed before cleanup completes", svc.StopGracePeriod),
				Remediation: "Set stop_grace_period to at least 10s for services that need graceful shutdown",
			})
		}
		if isLongGrace(svc.StopGracePeriod) {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "stop_grace_long",
				Severity:    "low",
				Detail:      fmt.Sprintf("stop_grace_period=%s is very long; deployments and restarts will be slow", svc.StopGracePeriod),
				Remediation: "Consider reducing stop_grace_period to 30-60s unless the service genuinely needs extended shutdown time",
			})
		}
	}

	return sr
}

func isShortGrace(d string) bool {
	s := strings.TrimSpace(d)
	if strings.HasSuffix(s, "ms") {
		return true
	}
	if strings.HasSuffix(s, "s") {
		val := strings.TrimSuffix(s, "s")
		if n, err := strconv.Atoi(val); err == nil && n < 5 {
			return true
		}
	}
	if n, err := strconv.Atoi(s); err == nil && n < 5 {
		return true
	}
	return false
}

func isLongGrace(d string) bool {
	s := strings.TrimSpace(d)
	if strings.HasSuffix(s, "m") {
		val := strings.TrimSuffix(s, "m")
		if n, err := strconv.Atoi(val); err == nil && n > 2 {
			return true
		}
	}
	if strings.HasSuffix(s, "s") {
		val := strings.TrimSuffix(s, "s")
		if n, err := strconv.Atoi(val); err == nil && n > 120 {
			return true
		}
	}
	if n, err := strconv.Atoi(s); err == nil && n > 120 {
		return true
	}
	return false
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Stop Signal / Grace Period Audit (%d services, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.TotalFindings)

	fmt.Fprintf(&b, "  SIGKILL stop signal:      %d\n", r.Summary.SigkillSignal)
	fmt.Fprintf(&b, "  Short grace period (<5s):  %d\n", r.Summary.ShortGrace)
	fmt.Fprintf(&b, "  Long grace period (>120s): %d\n", r.Summary.LongGrace)
	fmt.Fprintf(&b, "  Missing grace period:      %d\n\n", r.Summary.MissingGrace)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%s)\n", s.Name, s.File)
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.RuleID, f.Detail)
			fmt.Fprintf(&b, "           Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
	return b.String()
}
