package composelint

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type LintFinding struct {
	File       string `json:"file"`
	Service    string `json:"service,omitempty"`
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion"`
}

type LintReport struct {
	Findings []LintFinding `json:"findings"`
	Summary  LintSummary   `json:"summary"`
}

type LintSummary struct {
	TotalFiles    int `json:"total_files"`
	TotalServices int `json:"total_services"`
	TotalFindings int `json:"total_findings"`
	Errors        int `json:"errors"`
	Warnings      int `json:"warnings"`
	Info          int `json:"info"`
}

func Analyze(collected *collect.Collected) LintReport {
	var findings []LintFinding
	totalServices := 0

	for _, cf := range collected.ComposeFiles {
		findings = append(findings, lintFile(&cf)...)
		totalServices += len(cf.Services)
	}

	summary := LintSummary{
		TotalFiles:    len(collected.ComposeFiles),
		TotalServices: totalServices,
		TotalFindings: len(findings),
	}
	for _, f := range findings {
		switch f.Severity {
		case "error":
			summary.Errors++
		case "warning":
			summary.Warnings++
		case "info":
			summary.Info++
		}
	}

	return LintReport{Findings: findings, Summary: summary}
}

func lintFile(cf *compose.File) []LintFinding {
	var findings []LintFinding

	if len(cf.Services) == 0 {
		findings = append(findings, LintFinding{
			File:       cf.Path,
			RuleID:     "lint_no_services",
			Severity:   "warning",
			Message:    "Compose file defines no services",
			Suggestion: "Add at least one service definition under the 'services' key",
		})
	}

	for i := range cf.Services {
		findings = append(findings, lintService(&cf.Services[i], cf.Path)...)
	}

	return findings
}

func lintService(svc *compose.Service, file string) []LintFinding {
	var findings []LintFinding

	if svc.Image == "" {
		findings = append(findings, LintFinding{
			File:       file,
			Service:    svc.Name,
			RuleID:     "lint_no_image",
			Severity:   "warning",
			Message:    "Service has no 'image' defined (may use build context)",
			Suggestion: "Specify an explicit 'image' for clarity and reproducibility",
		})
	}

	if svc.Image != "" {
		tag := imageTag(svc.Image)
		if tag == "latest" {
			findings = append(findings, LintFinding{
				File:       file,
				Service:    svc.Name,
				RuleID:     "lint_latest_tag",
				Severity:   "warning",
				Message:    fmt.Sprintf("Image %q uses :latest tag", svc.Image),
				Suggestion: "Pin to a specific version tag for reproducible builds (e.g. nginx:1.25-alpine)",
			})
		} else if tag == "" {
			findings = append(findings, LintFinding{
				File:       file,
				Service:    svc.Name,
				RuleID:     "lint_no_tag",
				Severity:   "warning",
				Message:    fmt.Sprintf("Image %q has no tag; defaults to :latest", svc.Image),
				Suggestion: "Add an explicit version tag for reproducible builds",
			})
		}
	}

	if svc.Healthcheck == nil {
		findings = append(findings, LintFinding{
			File:       file,
			Service:    svc.Name,
			RuleID:     "lint_no_healthcheck",
			Severity:   "info",
			Message:    "No healthcheck defined",
			Suggestion: "Add a healthcheck to enable automatic container recovery and readiness checks",
		})
	}

	if svc.Restart == "" {
		findings = append(findings, LintFinding{
			File:       file,
			Service:    svc.Name,
			RuleID:     "lint_no_restart_policy",
			Severity:   "info",
			Message:    "No restart policy configured",
			Suggestion: "Set restart: unless-stopped or restart: on-failure for production services",
		})
	}

	if svc.MemLimit == "" {
		findings = append(findings, LintFinding{
			File:       file,
			Service:    svc.Name,
			RuleID:     "lint_no_mem_limit",
			Severity:   "warning",
			Message:    "No memory limit configured",
			Suggestion: "Set mem_limit or deploy.resources.limits.memory to prevent unbounded memory use",
		})
	}

	return findings
}

func imageTag(image string) string {
	// Handle digests (image@sha256:...)
	if strings.Contains(image, "@") {
		return "pinned-digest"
	}
	parts := strings.SplitN(image, ":", 2)
	if len(parts) == 1 {
		return ""
	}
	return parts[1]
}

func FormatText(r LintReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Compose Lint (%d files, %d services, %d findings)\n\n",
		r.Summary.TotalFiles, r.Summary.TotalServices, r.Summary.TotalFindings)

	fmt.Fprintf(&b, "  Errors: %d   Warnings: %d   Info: %d\n\n",
		r.Summary.Errors, r.Summary.Warnings, r.Summary.Info)

	for _, f := range r.Findings {
		svc := f.Service
		if svc == "" {
			svc = "(file-level)"
		}
		fmt.Fprintf(&b, "  [%s] %s — %s: %s\n", f.Severity, svc, f.RuleID, f.Message)
		fmt.Fprintf(&b, "         Fix: %s\n", f.Suggestion)
	}
	if len(r.Findings) > 0 {
		b.WriteString("\n")
	}
	return b.String()
}
