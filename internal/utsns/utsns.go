package utsns

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
	UtsMode  string    `json:"uts_mode,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	HostUtsNamespace int `json:"host_uts_namespace"`
	HostnameExposed  int `json:"hostname_exposed"`
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
			switch f.RuleID {
			case "utsns_host_uts":
				summary.HostUtsNamespace++
			case "utsns_hostname_env":
				summary.HostnameExposed++
			}
		}
		summary.TotalFindings += len(s.Findings)
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:    svc.Name,
		File:    file,
		UtsMode: svc.UtsMode,
	}

	if strings.EqualFold(svc.UtsMode, "host") {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "utsns_host_uts",
			Severity:    "high",
			Detail:      "Service uses host UTS namespace — shares hostname and domain with host, enabling hostname spoofing",
			Remediation: "Remove uts: host; use container-scoped UTS namespace for hostname isolation",
		})
	}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToUpper(parts[0])
		val := strings.ToLower(parts[1])
		if (key == "HOSTNAME" || key == "DOMAINNAME") && (strings.Contains(val, "host") || strings.Contains(val, "$(hostname)")) {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "utsns_hostname_env",
				Severity:    "medium",
				Detail:      fmt.Sprintf("Environment variable %s references host identity: '%s'", key, parts[1]),
				Remediation: "Use container-specific hostnames; avoid passing host identity into containers",
			})
		}
	}

	if svc.NetworkMode == "host" && svc.UtsMode == "" {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "utsns_network_host_uts_leak",
			Severity:    "medium",
			Detail:      "Service uses host network mode without explicit UTS isolation — hostname may leak from host network stack",
			Remediation: "Set uts: '' explicitly or ensure hostname leakage is acceptable for this service",
		})
	}

	for _, vol := range svc.Volumes {
		hostPath := extractHostPath(vol)
		lower := strings.ToLower(hostPath)
		if lower == "/etc/hostname" || lower == "/etc/hosts" || lower == "/etc/resolv.conf" {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "utsns_host_identity_mount",
				Severity:    "medium",
				Detail:      fmt.Sprintf("Host identity file mounted into container: %s", hostPath),
				Remediation: fmt.Sprintf("Remove %s volume mount or mount read-only with :ro suffix", hostPath),
			})
		}
	}

	return sr
}

func extractHostPath(vol string) string {
	parts := strings.SplitN(vol, ":", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("UTS Namespace & Hostname Isolation Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Total services:          %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Host UTS namespace:      %d\n", r.Summary.HostUtsNamespace)
	fmt.Fprintf(&b, "  Hostname exposed:        %d\n", r.Summary.HostnameExposed)
	fmt.Fprintf(&b, "  Total findings:          %d\n\n", r.Summary.TotalFindings)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s (%s)\n", s.Name, s.File)
		if s.UtsMode != "" {
			fmt.Fprintf(&b, "    UTS mode: %s\n", s.UtsMode)
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Detail)
			fmt.Fprintf(&b, "      Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}

	return b.String()
}
