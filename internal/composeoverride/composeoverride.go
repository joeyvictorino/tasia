package composeoverride

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type OverrideFinding struct {
	File       string `json:"file"`
	Service    string `json:"service"`
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Detail     string `json:"detail"`
	Remediation string `json:"remediation"`
}

type Summary struct {
	OverrideFiles int `json:"override_files"`
	TotalServices int `json:"total_services"`
	TotalFindings int `json:"total_findings"`
	HighRisk      int `json:"high_risk"`
	Score         int `json:"score"`
}

type Report struct {
	Findings []OverrideFinding `json:"findings"`
	Summary  Summary           `json:"summary"`
}

func isOverrideFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "override") ||
		strings.Contains(lower, ".override.") ||
		strings.HasSuffix(lower, ".dev.yml") ||
		strings.HasSuffix(lower, ".dev.yaml") ||
		strings.HasSuffix(lower, ".local.yml") ||
		strings.HasSuffix(lower, ".local.yaml")
}

func Analyze(collected *collect.Collected) Report {
	var findings []OverrideFinding
	overrideCount := 0
	svcCount := 0

	for _, cf := range collected.ComposeFiles {
		if !isOverrideFile(cf.Path) {
			continue
		}
		overrideCount++
		for _, svc := range cf.Services {
			svcCount++
			findings = append(findings, checkService(cf.Path, svc)...)
		}
	}

	high := 0
	for _, f := range findings {
		if f.Severity == "high" || f.Severity == "critical" {
			high++
		}
	}

	score := 100
	score -= high * 20
	score -= (len(findings) - high) * 10
	if score < 0 {
		score = 0
	}

	return Report{
		Findings: findings,
		Summary: Summary{
			OverrideFiles: overrideCount,
			TotalServices: svcCount,
			TotalFindings: len(findings),
			HighRisk:      high,
			Score:         score,
		},
	}
}

func checkService(file string, svc compose.Service) []OverrideFinding {
	var findings []OverrideFinding

	if svc.Privileged {
		findings = append(findings, OverrideFinding{
			File: file, Service: svc.Name,
			RuleID:   "override_privileged",
			Severity: "critical",
			Detail:   "Override enables privileged mode",
			Remediation: "Remove privileged: true from override; use specific capabilities instead",
		})
	}

	if svc.NetworkMode == "host" {
		findings = append(findings, OverrideFinding{
			File: file, Service: svc.Name,
			RuleID:   "override_host_network",
			Severity: "high",
			Detail:   "Override uses host network mode",
			Remediation: "Use bridge networking with explicit port mappings",
		})
	}

	if svc.PidMode == "host" {
		findings = append(findings, OverrideFinding{
			File: file, Service: svc.Name,
			RuleID:   "override_host_pid",
			Severity: "high",
			Detail:   "Override uses host PID namespace",
			Remediation: "Remove pid: host; it exposes all host processes",
		})
	}

	for _, vol := range svc.Volumes {
		if isWritableSensitiveMount(vol) {
			findings = append(findings, OverrideFinding{
				File: file, Service: svc.Name,
				RuleID:   "override_sensitive_volume",
				Severity: "critical",
				Detail:   fmt.Sprintf("Override mounts sensitive path: %s", vol),
				Remediation: "Avoid mounting /, /etc, /var/run/docker.sock or home directories writable",
			})
		}
	}

	for _, port := range svc.Ports {
		if isExposedDebugPort(port.Raw) {
			findings = append(findings, OverrideFinding{
				File: file, Service: svc.Name,
				RuleID:   "override_debug_port",
				Severity: "medium",
				Detail:   fmt.Sprintf("Override exposes debug/admin port: %s", port.Raw),
				Remediation: "Remove debug ports from override files used in production",
			})
		}
	}

	for _, envEntry := range svc.Environment {
		lk := strings.ToLower(envEntry)
		if strings.Contains(lk, "debug") && strings.Contains(lk, "true") {
			findings = append(findings, OverrideFinding{
				File: file, Service: svc.Name,
				RuleID:   "override_debug_env",
				Severity: "medium",
				Detail:   fmt.Sprintf("Override sets debug variable: %s", envEntry),
				Remediation: "Ensure debug variables are not set in production overrides",
			})
		}
	}

	if hasSecurityRelaxation(svc) {
		findings = append(findings, OverrideFinding{
			File: file, Service: svc.Name,
			RuleID:   "override_security_opt",
			Severity: "high",
			Detail:   "Override relaxes security options (apparmor/seccomp/selinux)",
			Remediation: "Do not disable security profiles in overrides",
		})
	}

	return findings
}

func isWritableSensitiveMount(vol string) bool {
	parts := strings.Split(vol, ":")
	if len(parts) < 2 {
		return false
	}
	src := parts[0]
	readOnly := len(parts) >= 3 && parts[2] == "ro"
	if readOnly {
		return false
	}
	sensitives := []string{"/", "/etc", "/var/run/docker.sock", "/root", "/home"}
	for _, s := range sensitives {
		if src == s {
			return true
		}
	}
	return false
}

func isExposedDebugPort(port string) bool {
	debugPorts := []string{"5005", "9229", "8787", "5678", "4200", "3000", "8080"}
	for _, dp := range debugPorts {
		if strings.Contains(port, dp) {
			return true
		}
	}
	return false
}

func hasSecurityRelaxation(svc compose.Service) bool {
	for _, opt := range svc.SecurityOpt {
		lower := strings.ToLower(opt)
		if strings.Contains(lower, "unconfined") || strings.Contains(lower, "no-new-privileges:false") {
			return true
		}
	}
	return false
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Compose Override Security Report\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&sb, "  Override files: %d\n", r.Summary.OverrideFiles)
	fmt.Fprintf(&sb, "  Services:       %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&sb, "  Findings:       %d\n", r.Summary.TotalFindings)
	fmt.Fprintf(&sb, "  High risk:      %d\n", r.Summary.HighRisk)
	fmt.Fprintf(&sb, "  Score:          %d/100\n\n", r.Summary.Score)

	if len(r.Findings) == 0 {
		sb.WriteString("  No security-weakening overrides detected.\n")
		return sb.String()
	}

	for i, f := range r.Findings {
		fmt.Fprintf(&sb, "  %d. [%s] %s in %s\n", i+1, strings.ToUpper(f.Severity), f.RuleID, f.Service)
		fmt.Fprintf(&sb, "     File: %s\n", f.File)
		fmt.Fprintf(&sb, "     %s\n", f.Detail)
		fmt.Fprintf(&sb, "     Fix: %s\n\n", f.Remediation)
	}

	return sb.String()
}
