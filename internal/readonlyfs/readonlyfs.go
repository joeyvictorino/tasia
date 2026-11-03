package readonlyfs

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service     string `json:"service"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Name     string    `json:"name"`
	ReadOnly bool      `json:"read_only"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices int `json:"total_services"`
	ReadOnlyCount int `json:"readonly_count"`
	WritableCount int `json:"writable_count"`
	TotalFindings int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func Analyze(c *collect.Collected) Report {
	var services []ServiceResult

	for _, comp := range c.ComposeFiles {
		for _, svc := range comp.Services {
			sr := analyzeService(svc)
			services = append(services, sr)
		}
	}

	summary := Summary{TotalServices: len(services)}
	for _, s := range services {
		if s.ReadOnly {
			summary.ReadOnlyCount++
		} else {
			summary.WritableCount++
		}
		summary.TotalFindings += len(s.Findings)
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{
		Name:     svc.Name,
		ReadOnly: svc.ReadOnly,
	}

	if !svc.ReadOnly {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			RuleID:      "readonly_fs_missing",
			Severity:    "medium",
			Detail:      fmt.Sprintf("Service %q does not set read_only: true", svc.Name),
			Remediation: "Add read_only: true to the service definition and use tmpfs/volumes for writable paths",
		})
	}

	for _, vol := range svc.Volumes {
		if isWritableBindMount(vol) {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				RuleID:      "readonly_writable_bind",
				Severity:    "low",
				Detail:      fmt.Sprintf("Service %q has writable bind mount: %s", svc.Name, vol),
				Remediation: "Add :ro suffix to bind mounts that don't need write access",
			})
		}
	}

	if svc.ReadOnly && len(svc.Tmpfs) == 0 {
		needsTmpfs := false
		for _, vol := range svc.Volumes {
			if strings.Contains(vol, "/tmp") || strings.Contains(vol, "/run") {
				needsTmpfs = true
				break
			}
		}
		if !needsTmpfs {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				RuleID:      "readonly_no_tmpfs",
				Severity:    "info",
				Detail:      fmt.Sprintf("Service %q is read-only but has no tmpfs mounts for /tmp or /run", svc.Name),
				Remediation: "Add tmpfs mounts for /tmp and /run to avoid write failures in read-only containers",
			})
		}
	}

	return sr
}

func isWritableBindMount(vol string) bool {
	parts := strings.Split(vol, ":")
	if len(parts) < 2 {
		return false
	}
	if len(parts) >= 3 && strings.Contains(parts[2], "ro") {
		return false
	}
	if strings.HasPrefix(parts[0], "/") || strings.HasPrefix(parts[0], "./") || strings.HasPrefix(parts[0], "../") {
		return true
	}
	return false
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Read-Only Filesystem Analysis\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&sb, "  Services:   %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&sb, "  Read-only:  %d\n", r.Summary.ReadOnlyCount)
	fmt.Fprintf(&sb, "  Writable:   %d\n", r.Summary.WritableCount)
	fmt.Fprintf(&sb, "  Findings:   %d\n\n", r.Summary.TotalFindings)

	for _, s := range r.Services {
		status := "WRITABLE"
		if s.ReadOnly {
			status = "READ-ONLY"
		}
		fmt.Fprintf(&sb, "  [%s] %s\n", status, s.Name)
		for _, f := range s.Findings {
			fmt.Fprintf(&sb, "    - [%s] %s: %s\n", f.Severity, f.RuleID, f.Detail)
		}
	}
	return sb.String()
}

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
