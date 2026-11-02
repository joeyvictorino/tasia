package entrypoint

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

var dangerousCommands = map[string]string{
	"curl":    "network fetch in entrypoint may download untrusted code",
	"wget":    "network fetch in entrypoint may download untrusted code",
	"eval":    "eval in entrypoint enables arbitrary code execution",
	"ssh":     "SSH in entrypoint may leak credentials or enable lateral movement",
	"nc":      "netcat in entrypoint can create unauthorized network channels",
	"ncat":    "netcat in entrypoint can create unauthorized network channels",
	"python":  "interpreter in entrypoint may execute untrusted code",
	"python3": "interpreter in entrypoint may execute untrusted code",
	"node":    "interpreter in entrypoint may execute untrusted code",
	"bash -c": "shell -c in entrypoint enables injection via environment variables",
	"sh -c":   "shell -c in entrypoint enables injection via environment variables",
}

var sensitiveEnvPatterns = []string{
	"$PASSWORD", "$SECRET", "$TOKEN", "$KEY", "$CREDENTIAL", "$API_KEY",
	"${PASSWORD", "${SECRET", "${TOKEN", "${KEY", "${CREDENTIAL", "${API_KEY",
}

type Finding struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	Severity string `json:"severity"`
	RuleID   string `json:"rule_id"`
	Detail   string `json:"detail"`
}

type ServiceResult struct {
	Name       string   `json:"name"`
	File       string   `json:"file"`
	Entrypoint []string `json:"entrypoint,omitempty"`
	Command    []string `json:"command,omitempty"`
	Findings   []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices  int `json:"total_services"`
	WithEntrypoint int `json:"with_entrypoint"`
	WithCommand    int `json:"with_command"`
	WithIssues     int `json:"with_issues"`
	TotalFindings  int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func Analyze(collected *collect.Collected) Report {
	var results []ServiceResult
	var total, withEP, withCmd, withIssues, totalFindings int

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			total++
			sr := ServiceResult{
				Name:       svc.Name,
				File:       cf.Path,
				Entrypoint: svc.Entrypoint,
				Command:    svc.Command,
			}
			if len(svc.Entrypoint) > 0 {
				withEP++
			}
			if len(svc.Command) > 0 {
				withCmd++
			}

			// Check entrypoint for shell form (single string with spaces = shell form)
			if len(svc.Entrypoint) == 1 && strings.Contains(svc.Entrypoint[0], " ") {
				sr.Findings = append(sr.Findings, Finding{
					Service:  svc.Name,
					File:     cf.Path,
					Severity: "medium",
					RuleID:   "entrypoint_shell_form",
					Detail:   "entrypoint uses shell form; prefer exec form [\"cmd\", \"arg\"] to avoid signal handling issues",
				})
			}

			// Check command for shell form
			if len(svc.Command) == 1 && strings.Contains(svc.Command[0], " ") {
				sr.Findings = append(sr.Findings, Finding{
					Service:  svc.Name,
					File:     cf.Path,
					Severity: "low",
					RuleID:   "command_shell_form",
					Detail:   "command uses shell form; prefer exec form for proper signal propagation",
				})
			}

			// Check for dangerous commands in entrypoint/command
			allParts := joinParts(svc.Entrypoint, svc.Command)
			for cmd, reason := range dangerousCommands {
				if containsCommand(allParts, cmd) {
					sr.Findings = append(sr.Findings, Finding{
						Service:  svc.Name,
						File:     cf.Path,
						Severity: "high",
						RuleID:   "entrypoint_dangerous_cmd",
						Detail:   fmt.Sprintf("dangerous command '%s' in entrypoint/command: %s", cmd, reason),
					})
				}
			}

			// Check for sensitive env var references in entrypoint/command
			joined := strings.Join(allParts, " ")
			for _, pat := range sensitiveEnvPatterns {
				if strings.Contains(strings.ToUpper(joined), strings.ToUpper(pat)) {
					sr.Findings = append(sr.Findings, Finding{
						Service:  svc.Name,
						File:     cf.Path,
						Severity: "high",
						RuleID:   "entrypoint_secret_ref",
						Detail:   fmt.Sprintf("entrypoint/command references sensitive environment variable matching '%s'", pat),
					})
					break
				}
			}

			// Check for running as root indicators
			if containsCommand(allParts, "sudo") {
				sr.Findings = append(sr.Findings, Finding{
					Service:  svc.Name,
					File:     cf.Path,
					Severity: "high",
					RuleID:   "entrypoint_sudo",
					Detail:   "entrypoint/command uses sudo; container should run as non-root instead",
				})
			}

			// Check for sleep-based polling (bad pattern in agent containers)
			if containsCommand(allParts, "sleep") && (containsCommand(allParts, "while") || containsCommand(allParts, "loop")) {
				sr.Findings = append(sr.Findings, Finding{
					Service:  svc.Name,
					File:     cf.Path,
					Severity: "low",
					RuleID:   "entrypoint_sleep_poll",
					Detail:   "entrypoint/command appears to use sleep-based polling; consider healthcheck or event-driven approach",
				})
			}

			if len(sr.Findings) > 0 {
				withIssues++
				totalFindings += len(sr.Findings)
			}
			results = append(results, sr)
		}
	}

	return Report{
		Services: results,
		Summary: Summary{
			TotalServices:  total,
			WithEntrypoint: withEP,
			WithCommand:    withCmd,
			WithIssues:     withIssues,
			TotalFindings:  totalFindings,
		},
	}
}

func joinParts(ep, cmd []string) []string {
	var parts []string
	parts = append(parts, ep...)
	parts = append(parts, cmd...)
	return parts
}

func containsCommand(parts []string, cmd string) bool {
	joined := strings.Join(parts, " ")
	lower := strings.ToLower(joined)
	cmdLower := strings.ToLower(cmd)
	return strings.Contains(lower, cmdLower)
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Entrypoint & Command Security Analysis\n")
	sb.WriteString(strings.Repeat("=", 62) + "\n\n")
	sb.WriteString(fmt.Sprintf("  Total services:        %d\n", r.Summary.TotalServices))
	sb.WriteString(fmt.Sprintf("  With entrypoint:       %d\n", r.Summary.WithEntrypoint))
	sb.WriteString(fmt.Sprintf("  With command:          %d\n", r.Summary.WithCommand))
	sb.WriteString(fmt.Sprintf("  Services with issues:  %d\n", r.Summary.WithIssues))
	sb.WriteString(fmt.Sprintf("  Total findings:        %d\n\n", r.Summary.TotalFindings))

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s (%s)\n", sr.Name, sr.File))
		if len(sr.Entrypoint) > 0 {
			sb.WriteString(fmt.Sprintf("    entrypoint: %s\n", strings.Join(sr.Entrypoint, " ")))
		}
		if len(sr.Command) > 0 {
			sb.WriteString(fmt.Sprintf("    command: %s\n", strings.Join(sr.Command, " ")))
		}
		for _, f := range sr.Findings {
			sb.WriteString(fmt.Sprintf("    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Detail))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
