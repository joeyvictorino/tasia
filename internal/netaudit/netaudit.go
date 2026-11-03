package netaudit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	Severity string `json:"severity"`
	RuleID   string `json:"rule_id"`
	Detail   string `json:"detail"`
}

type ServiceResult struct {
	Name        string    `json:"name"`
	File        string    `json:"file"`
	NetworkMode string    `json:"network_mode,omitempty"`
	HasPorts    bool      `json:"has_ports"`
	Findings    []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices  int `json:"total_services"`
	WithHostNet    int `json:"with_host_network"`
	WithPorts      int `json:"with_ports"`
	WithIssues     int `json:"with_issues"`
	TotalFindings  int `json:"total_findings"`
	NetworksDefined int `json:"networks_defined"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func Analyze(collected *collect.Collected) Report {
	var results []ServiceResult
	var totalSvcs, hostNet, withPorts, withIssues, totalFindings, netsDefined int

	for i := range collected.ComposeFiles {
		cf := &collected.ComposeFiles[i]
		netsDefined += len(cf.Networks)
		hasNamedNetworks := len(cf.Networks) > 0

		for _, svc := range cf.Services {
			totalSvcs++
			sr := ServiceResult{
				Name:        svc.Name,
				File:        cf.Path,
				NetworkMode: svc.NetworkMode,
				HasPorts:    len(svc.Ports) > 0,
			}
			if sr.HasPorts {
				withPorts++
			}

			findings := analyzeService(svc, cf, hasNamedNetworks)
			sr.Findings = findings
			if len(findings) > 0 {
				withIssues++
				totalFindings += len(findings)
			}
			if svc.NetworkMode == "host" {
				hostNet++
			}
			results = append(results, sr)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return len(results[i].Findings) > len(results[j].Findings)
	})

	return Report{
		Services: results,
		Summary: Summary{
			TotalServices:   totalSvcs,
			WithHostNet:     hostNet,
			WithPorts:       withPorts,
			WithIssues:      withIssues,
			TotalFindings:   totalFindings,
			NetworksDefined: netsDefined,
		},
	}
}

func analyzeService(svc compose.Service, cf *compose.File, hasNamedNetworks bool) []Finding {
	var findings []Finding

	if svc.NetworkMode == "host" && len(svc.Ports) > 0 {
		findings = append(findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "high",
			RuleID:   "net_host_with_ports",
			Detail:   "service uses network_mode: host with published ports (ports are ignored in host mode)",
		})
	}

	if svc.NetworkMode == "host" {
		findings = append(findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "medium",
			RuleID:   "net_host_mode",
			Detail:   "service uses host networking, bypassing Docker network isolation",
		})
	}

	if svc.Privileged && svc.NetworkMode != "none" {
		findings = append(findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "high",
			RuleID:   "net_privileged_network",
			Detail:   "privileged container has full network access; consider network_mode: none or restricting capabilities",
		})
	}

	if !hasNamedNetworks && svc.NetworkMode == "" {
		findings = append(findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "low",
			RuleID:   "net_default_bridge",
			Detail:   "no named networks defined; all services share default bridge network",
		})
	}

	if hasPublicPort(svc.Ports) && !svc.ReadOnly {
		findings = append(findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "medium",
			RuleID:   "net_public_writable",
			Detail:   "service exposes public ports without read-only root filesystem",
		})
	}

	if hasWideHostBind(svc.Ports) {
		findings = append(findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "medium",
			RuleID:   "net_wide_bind",
			Detail:   "service binds to 0.0.0.0 (all interfaces); consider binding to 127.0.0.1 for internal services",
		})
	}

	return findings
}

func hasPublicPort(ports []compose.PortMapping) bool {
	for _, p := range ports {
		if p.HostPort > 0 {
			return true
		}
	}
	return false
}

func hasWideHostBind(ports []compose.PortMapping) bool {
	for _, p := range ports {
		if p.HostPort > 0 && (p.HostIP == "" || p.HostIP == "0.0.0.0") {
			return true
		}
	}
	return false
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Network Configuration Audit\n")
	sb.WriteString(strings.Repeat("=", 62) + "\n\n")
	sb.WriteString(fmt.Sprintf("  Total services:      %d\n", r.Summary.TotalServices))
	sb.WriteString(fmt.Sprintf("  Host networking:     %d\n", r.Summary.WithHostNet))
	sb.WriteString(fmt.Sprintf("  With ports:          %d\n", r.Summary.WithPorts))
	sb.WriteString(fmt.Sprintf("  Networks defined:    %d\n", r.Summary.NetworksDefined))
	sb.WriteString(fmt.Sprintf("  Services with issues: %d\n", r.Summary.WithIssues))
	sb.WriteString(fmt.Sprintf("  Total findings:      %d\n\n", r.Summary.TotalFindings))

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s (%s):\n", sr.Name, sr.File))
		for _, f := range sr.Findings {
			sb.WriteString(fmt.Sprintf("    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Detail))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
