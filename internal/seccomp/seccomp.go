package seccomp

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Detail   string `json:"detail"`
}

type ServiceResult struct {
	Name           string    `json:"name"`
	File           string    `json:"file"`
	SeccompProfile string    `json:"seccomp_profile,omitempty"`
	Privileged     bool      `json:"privileged"`
	Findings       []Finding `json:"findings,omitempty"`
	Score          int       `json:"score"`
	Grade          string    `json:"grade"`
}

type Summary struct {
	TotalServices       int `json:"total_services"`
	WithSeccomp         int `json:"with_seccomp"`
	WithUnconfined      int `json:"with_unconfined"`
	WithCustomProfile   int `json:"with_custom_profile"`
	WithNoSeccomp       int `json:"with_no_seccomp"`
	WithIssues          int `json:"with_issues"`
	TotalFindings       int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func Analyze(collected collect.Collected) Report {
	var services []ServiceResult

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf)
			services = append(services, sr)
		}
	}

	summary := buildSummary(services)

	return Report{
		Services: services,
		Summary:  summary,
	}
}

func analyzeService(svc compose.Service, cf compose.File) ServiceResult {
	sr := ServiceResult{
		Name:       svc.Name,
		File:       cf.Path,
		Privileged: svc.Privileged,
		Score:      100,
	}

	profile := extractSeccompProfile(svc.SecurityOpt)
	sr.SeccompProfile = profile

	if profile == "" && !svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "low",
			Category: "no_seccomp_profile",
			Detail:   fmt.Sprintf("Service '%s' has no explicit seccomp profile; relies on Docker default", svc.Name),
		})
		sr.Score -= 10
	}

	if profile == "unconfined" {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "high",
			Category: "seccomp_unconfined",
			Detail:   fmt.Sprintf("Service '%s' has seccomp:unconfined, disabling all syscall filtering", svc.Name),
		})
		sr.Score -= 40
	}

	if svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "high",
			Category: "privileged_bypasses_seccomp",
			Detail:   fmt.Sprintf("Service '%s' is privileged, which implicitly disables seccomp filtering", svc.Name),
		})
		sr.Score -= 30
	}

	if profile == "unconfined" && svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "critical",
			Category: "privileged_unconfined",
			Detail:   fmt.Sprintf("Service '%s' is privileged with explicit seccomp:unconfined — maximum syscall exposure", svc.Name),
		})
		sr.Score -= 20
	}

	if hasAppArmorDisabled(svc.SecurityOpt) {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "medium",
			Category: "apparmor_disabled",
			Detail:   fmt.Sprintf("Service '%s' has AppArmor set to unconfined, removing MAC enforcement", svc.Name),
		})
		sr.Score -= 15
	}

	if hasNoNewPrivilegesDisabled(svc.SecurityOpt) {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "medium",
			Category: "no_new_privileges_disabled",
			Detail:   fmt.Sprintf("Service '%s' has no-new-privileges:false, allowing privilege escalation via setuid/setgid", svc.Name),
		})
		sr.Score -= 15
	}

	if sr.Score < 0 {
		sr.Score = 0
	}
	sr.Grade = scoreToGrade(sr.Score)
	return sr
}

func extractSeccompProfile(secOpts []string) string {
	for _, opt := range secOpts {
		lower := strings.ToLower(opt)
		if strings.HasPrefix(lower, "seccomp=") || strings.HasPrefix(lower, "seccomp:") {
			parts := strings.SplitN(opt, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
			parts = strings.SplitN(opt, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func hasAppArmorDisabled(secOpts []string) bool {
	for _, opt := range secOpts {
		lower := strings.ToLower(opt)
		if (strings.HasPrefix(lower, "apparmor=") || strings.HasPrefix(lower, "apparmor:")) &&
			strings.Contains(lower, "unconfined") {
			return true
		}
	}
	return false
}

func hasNoNewPrivilegesDisabled(secOpts []string) bool {
	for _, opt := range secOpts {
		lower := strings.ToLower(opt)
		if strings.Contains(lower, "no-new-privileges") && strings.Contains(lower, "false") {
			return true
		}
	}
	return false
}

func buildSummary(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		if sr.SeccompProfile != "" {
			s.WithSeccomp++
			if sr.SeccompProfile == "unconfined" {
				s.WithUnconfined++
			} else {
				s.WithCustomProfile++
			}
		} else if !sr.Privileged {
			s.WithNoSeccomp++
		}
		if len(sr.Findings) > 0 {
			s.WithIssues++
		}
		s.TotalFindings += len(sr.Findings)
	}
	return s
}

func scoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Seccomp Profile Audit\n")
	b.WriteString(strings.Repeat("=", 40) + "\n")
	fmt.Fprintf(&b, "Services scanned:      %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "With seccomp profile:  %d\n", r.Summary.WithSeccomp)
	fmt.Fprintf(&b, "  Unconfined:          %d\n", r.Summary.WithUnconfined)
	fmt.Fprintf(&b, "  Custom profile:      %d\n", r.Summary.WithCustomProfile)
	fmt.Fprintf(&b, "No explicit seccomp:   %d\n", r.Summary.WithNoSeccomp)
	fmt.Fprintf(&b, "Total findings:        %d\n\n", r.Summary.TotalFindings)

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%s) [%s]\n", sr.Name, sr.File, sr.Grade)
		if sr.SeccompProfile != "" {
			fmt.Fprintf(&b, "    seccomp: %s\n", sr.SeccompProfile)
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.Category, f.Detail)
		}
		b.WriteString("\n")
	}
	return b.String()
}
