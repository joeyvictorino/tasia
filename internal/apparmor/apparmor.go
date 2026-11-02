package apparmor

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
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
	Profile     string `json:"profile,omitempty"`
}

type ServiceResult struct {
	Name     string   `json:"name"`
	File     string   `json:"file"`
	Profile  string   `json:"profile,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	WithProfile      int `json:"with_profile"`
	WithoutProfile   int `json:"without_profile"`
	Unconfined       int `json:"unconfined"`
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
		if s.Profile != "" {
			summary.WithProfile++
		} else {
			summary.WithoutProfile++
		}
		summary.TotalFindings += len(s.Findings)
		for _, f := range s.Findings {
			if f.RuleID == "apparmor_unconfined" {
				summary.Unconfined++
			}
		}
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name: svc.Name,
		File: file,
	}

	var apparmorProfile string
	for _, opt := range svc.SecurityOpt {
		lower := strings.ToLower(opt)
		if strings.HasPrefix(lower, "apparmor=") || strings.HasPrefix(lower, "apparmor:") {
			apparmorProfile = opt[len("apparmor="):]
			if strings.HasPrefix(lower, "apparmor:") {
				apparmorProfile = opt[len("apparmor:"):]
			}
			break
		}
	}

	sr.Profile = apparmorProfile

	if apparmorProfile == "" {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "apparmor_missing",
			Severity:    "medium",
			Detail:      "No AppArmor profile configured; container runs with default Docker profile which may be overly permissive",
			Remediation: "Add security_opt: [\"apparmor=docker-default\"] or a custom profile to restrict container capabilities",
		})
	} else if strings.ToLower(apparmorProfile) == "unconfined" {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "apparmor_unconfined",
			Severity:    "high",
			Profile:     apparmorProfile,
			Detail:      "AppArmor profile set to 'unconfined'; container has no mandatory access control restrictions",
			Remediation: "Use 'docker-default' or a custom AppArmor profile instead of 'unconfined'",
		})
	}

	if svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "apparmor_privileged",
			Severity:    "critical",
			Profile:     apparmorProfile,
			Detail:      "Privileged container; AppArmor profile is bypassed regardless of configuration",
			Remediation: "Remove privileged: true to allow AppArmor enforcement",
		})
	}

	for _, opt := range svc.SecurityOpt {
		lower := strings.ToLower(opt)
		if lower == "no-new-privileges" || lower == "no-new-privileges:true" || lower == "no-new-privileges=true" {
			continue
		}
		if strings.HasPrefix(lower, "apparmor") {
			continue
		}
		if strings.HasPrefix(lower, "label") {
			continue
		}
		if strings.HasPrefix(lower, "seccomp") {
			continue
		}
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "apparmor_unknown_secopt",
			Severity:    "low",
			Detail:      fmt.Sprintf("Unknown security_opt entry '%s'; verify it is intentional", opt),
			Remediation: "Review security_opt entries and remove any that are not required",
		})
	}

	return sr
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "AppArmor Profile Audit (%d services, %d with profiles, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.WithProfile, r.Summary.TotalFindings)

	fmt.Fprintf(&b, "  Without profile:  %d\n", r.Summary.WithoutProfile)
	fmt.Fprintf(&b, "  Unconfined:       %d\n\n", r.Summary.Unconfined)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		profile := s.Profile
		if profile == "" {
			profile = "(none)"
		}
		fmt.Fprintf(&b, "  %s (%s) profile=%s\n", s.Name, s.File, profile)
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.RuleID, f.Detail)
			fmt.Fprintf(&b, "           Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
	return b.String()
}
