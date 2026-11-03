package credscan

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type CredentialFinding struct {
	File       string `json:"file"`
	Line       int    `json:"line,omitempty"`
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Pattern    string `json:"pattern"`
	Context    string `json:"context"`
	Remediation string `json:"remediation"`
}

type Summary struct {
	FilesScanned   int `json:"files_scanned"`
	TotalFindings  int `json:"total_findings"`
	HighSeverity   int `json:"high_severity"`
	MediumSeverity int `json:"medium_severity"`
	LowSeverity    int `json:"low_severity"`
	Score          int `json:"score"`
}

type Report struct {
	Findings []CredentialFinding `json:"findings"`
	Summary  Summary             `json:"summary"`
}

type credPattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity string
	Remedy   string
}

var patterns = []credPattern{
	{"aws_access_key", regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`), "critical", "Use IAM roles or AWS Secrets Manager instead of hardcoded keys"},
	{"aws_secret_key", regexp.MustCompile(`(?i)(?:aws_secret|secret_access)[_\s]*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}`), "critical", "Use IAM roles or AWS Secrets Manager instead of hardcoded keys"},
	{"github_token", regexp.MustCompile(`(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`), "critical", "Use GitHub Apps or environment variables for tokens"},
	{"generic_api_key", regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}`), "high", "Move API keys to a secrets manager or encrypted environment variables"},
	{"generic_secret", regexp.MustCompile(`(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'"]{8,}`), "high", "Use a secrets manager; never hardcode passwords"},
	{"bearer_token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-.~+/]+=*`), "high", "Inject bearer tokens at runtime from a secrets vault"},
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), "critical", "Use a key management service; never embed private keys in config"},
	{"jwt_token", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "high", "JWTs should be generated at runtime, not stored in config"},
	{"slack_token", regexp.MustCompile(`xox[bpras]-[0-9]{10,}-[A-Za-z0-9-]+`), "critical", "Rotate this Slack token and use environment variables"},
	{"openai_key", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`), "critical", "Use environment variables for OpenAI API keys"},
	{"database_url", regexp.MustCompile(`(?i)(?:mysql|postgres|mongodb|redis)://[^\s'"]+:[^\s'"]+@`), "critical", "Use connection string references from secrets manager"},
	{"hex_secret", regexp.MustCompile(`(?i)(?:secret|token|key)\s*[:=]\s*['\"]?[a-f0-9]{32,}`), "medium", "Replace hardcoded hex secrets with runtime injection"},
}

func Analyze(collected *collect.Collected) Report {
	var findings []CredentialFinding
	fileCount := 0

	for _, ef := range collected.EnvFiles {
		fileCount++
		findings = append(findings, scanEnvFile(ef)...)
	}

	for _, df := range collected.Dockerfiles {
		fileCount++
		findings = append(findings, scanDockerfile(df)...)
	}

	for _, cf := range collected.ComposeFiles {
		fileCount++
		findings = append(findings, scanComposeFile(cf)...)
	}

	high, med, low := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case "critical", "high":
			high++
		case "medium":
			med++
		default:
			low++
		}
	}

	score := 100
	score -= high * 20
	score -= med * 10
	score -= low * 5
	if score < 0 {
		score = 0
	}

	return Report{
		Findings: findings,
		Summary: Summary{
			FilesScanned:   fileCount,
			TotalFindings:  len(findings),
			HighSeverity:   high,
			MediumSeverity: med,
			LowSeverity:    low,
			Score:          score,
		},
	}
}

func scanEnvFile(ef collect.EnvFile) []CredentialFinding {
	var findings []CredentialFinding
	for _, key := range ef.Keys {
		if key.ValuePattern != "" {
			findings = append(findings, CredentialFinding{
				File:       ef.Path,
				Line:       key.Line,
				RuleID:     "cred_env_secret_pattern",
				Severity:   "high",
				Pattern:    key.ValuePattern,
				Context:    fmt.Sprintf("key %q matches secret pattern %q", key.Name, key.ValuePattern),
				Remediation: "Use Docker secrets or a vault; avoid .env files for production secrets",
			})
		}
	}
	return findings
}

func scanDockerfile(df collect.Dockerfile) []CredentialFinding {
	var findings []CredentialFinding
	lines := strings.Split(df.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, p := range patterns {
			if p.Regex.MatchString(line) {
				findings = append(findings, CredentialFinding{
					File:       df.Path,
					Line:       i + 1,
					RuleID:     "cred_dockerfile_" + p.Name,
					Severity:   p.Severity,
					Pattern:    p.Name,
					Context:    truncateContext(line),
					Remediation: p.Remedy,
				})
			}
		}
		if strings.Contains(strings.ToUpper(trimmed), "ARG ") || strings.Contains(strings.ToUpper(trimmed), "ENV ") {
			for _, p := range patterns {
				if p.Regex.MatchString(line) {
					break
				}
			}
		}
	}
	return findings
}

func scanComposeFile(cf compose.File) []CredentialFinding {
	var findings []CredentialFinding
	for _, svc := range cf.Services {
		for _, entry := range svc.Environment {
			for _, p := range patterns {
				if p.Regex.MatchString(entry) {
					parts := strings.SplitN(entry, "=", 2)
					keyName := entry
					if len(parts) > 0 {
						keyName = parts[0]
					}
					findings = append(findings, CredentialFinding{
						File:       cf.Path,
						RuleID:     "cred_compose_" + p.Name,
						Severity:   p.Severity,
						Pattern:    p.Name,
						Context:    fmt.Sprintf("service %q env %s", svc.Name, keyName),
						Remediation: p.Remedy,
					})
				}
			}
		}
	}
	return findings
}

func truncateContext(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Credential Scan Report\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&sb, "  Files scanned: %d\n", r.Summary.FilesScanned)
	fmt.Fprintf(&sb, "  Findings:      %d\n", r.Summary.TotalFindings)
	fmt.Fprintf(&sb, "  High/Critical: %d\n", r.Summary.HighSeverity)
	fmt.Fprintf(&sb, "  Medium:        %d\n", r.Summary.MediumSeverity)
	fmt.Fprintf(&sb, "  Low:           %d\n", r.Summary.LowSeverity)
	fmt.Fprintf(&sb, "  Score:         %d/100\n\n", r.Summary.Score)

	if len(r.Findings) == 0 {
		sb.WriteString("  No credential leaks detected.\n")
		return sb.String()
	}

	for i, f := range r.Findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(&sb, "  %d. [%s] %s\n", i+1, strings.ToUpper(f.Severity), f.RuleID)
		fmt.Fprintf(&sb, "     Location: %s\n", loc)
		fmt.Fprintf(&sb, "     Pattern:  %s\n", f.Pattern)
		fmt.Fprintf(&sb, "     Context:  %s\n", f.Context)
		fmt.Fprintf(&sb, "     Fix:      %s\n\n", f.Remediation)
	}

	return sb.String()
}
