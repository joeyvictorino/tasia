package selinux

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
}

type ServiceResult struct {
	Name     string    `json:"name"`
	File     string    `json:"file"`
	Labels   []string  `json:"labels,omitempty"`
	Disabled bool      `json:"disabled"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices  int `json:"total_services"`
	WithLabels     int `json:"with_labels"`
	WithoutLabels  int `json:"without_labels"`
	Disabled       int `json:"disabled"`
	TotalFindings  int `json:"total_findings"`
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
		if s.Disabled {
			summary.Disabled++
		}
		if len(s.Labels) > 0 || s.Disabled {
			summary.WithLabels++
		} else {
			summary.WithoutLabels++
		}
		summary.TotalFindings += len(s.Findings)
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name: svc.Name,
		File: file,
	}

	var labelOpts []string
	for _, opt := range svc.SecurityOpt {
		lower := strings.ToLower(opt)
		if strings.HasPrefix(lower, "label=") || strings.HasPrefix(lower, "label:") {
			val := opt[len("label="):]
			if strings.HasPrefix(lower, "label:") {
				val = opt[len("label:"):]
			}
			labelOpts = append(labelOpts, val)
		}
	}

	for _, lo := range labelOpts {
		if strings.ToLower(lo) == "disable" {
			sr.Disabled = true
		}
	}
	sr.Labels = labelOpts

	if len(labelOpts) == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "selinux_no_labels",
			Severity:    "medium",
			Detail:      "No SELinux labels configured via security_opt; container relies on default context",
			Remediation: "Add security_opt: [\"label:type:container_t\"] or appropriate SELinux labels",
		})
	}

	if sr.Disabled {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "selinux_disabled",
			Severity:    "high",
			Detail:      "SELinux labeling disabled via label:disable; container runs without mandatory access control labels",
			Remediation: "Remove label:disable and configure appropriate SELinux type and level labels",
		})
	}

	for _, lo := range labelOpts {
		lower := strings.ToLower(lo)
		if lower == "disable" {
			continue
		}
		if strings.HasPrefix(lower, "type:") {
			typeName := lo[len("type:"):]
			if strings.HasSuffix(strings.ToLower(typeName), "_permissive_t") || strings.ToLower(typeName) == "permissive" {
				sr.Findings = append(sr.Findings, Finding{
					Service:     svc.Name,
					File:        file,
					RuleID:      "selinux_permissive_type",
					Severity:    "high",
					Detail:      fmt.Sprintf("SELinux type '%s' appears to be permissive; violations are logged but not enforced", typeName),
					Remediation: "Use an enforcing SELinux type such as container_t or a custom confined type",
				})
			}
		}
		if strings.HasPrefix(lower, "level:") {
			level := lo[len("level:"):]
			if !strings.Contains(level, ":c") && !strings.Contains(strings.ToLower(level), ":c") {
				sr.Findings = append(sr.Findings, Finding{
					Service:     svc.Name,
					File:        file,
					RuleID:      "selinux_no_mcs",
					Severity:    "low",
					Detail:      fmt.Sprintf("SELinux level '%s' has no MCS categories; containers may share access", level),
					Remediation: "Add MCS categories (e.g., level:s0:c100,c200) to isolate container access",
				})
			}
		}
	}

	if svc.Privileged && len(labelOpts) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "selinux_privileged",
			Severity:    "critical",
			Detail:      "Privileged container; SELinux labels are effectively bypassed",
			Remediation: "Remove privileged: true to allow SELinux enforcement",
		})
	}

	return sr
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SELinux Context Audit (%d services, %d with labels, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.WithLabels, r.Summary.TotalFindings)

	fmt.Fprintf(&b, "  Without labels:  %d\n", r.Summary.WithoutLabels)
	fmt.Fprintf(&b, "  Disabled:        %d\n\n", r.Summary.Disabled)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		labels := strings.Join(s.Labels, ", ")
		if labels == "" {
			labels = "(none)"
		}
		fmt.Fprintf(&b, "  %s (%s) labels=%s\n", s.Name, s.File, labels)
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.RuleID, f.Detail)
			fmt.Fprintf(&b, "           Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
	return b.String()
}
