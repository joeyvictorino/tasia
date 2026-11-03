package netns

import (
	"encoding/json"
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
	Name        string    `json:"name"`
	File        string    `json:"file"`
	NetworkMode string    `json:"network_mode,omitempty"`
	Findings    []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	HostNetwork      int `json:"host_network"`
	ContainerNetwork int `json:"container_network"`
	NoNetwork        int `json:"no_network"`
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
			case "netns_host_network":
				summary.HostNetwork++
			case "netns_container_network":
				summary.ContainerNetwork++
			case "netns_no_network":
				summary.NoNetwork++
			}
		}
		summary.TotalFindings += len(s.Findings)
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:        svc.Name,
		File:        file,
		NetworkMode: svc.NetworkMode,
	}

	if strings.EqualFold(svc.NetworkMode, "host") {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "netns_host_network",
			Severity:    "critical",
			Detail:      "Service uses host network namespace — all host network interfaces and ports are accessible",
			Remediation: "Remove network_mode: host; use bridge networking with explicit port mappings",
		})
	} else if strings.HasPrefix(svc.NetworkMode, "container:") {
		target := strings.TrimPrefix(svc.NetworkMode, "container:")
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "netns_container_network",
			Severity:    "high",
			Detail:      fmt.Sprintf("Service shares network namespace with container '%s' — network traffic visible across containers", target),
			Remediation: "Use separate bridge networks unless network sharing is required between these containers",
		})
	} else if strings.HasPrefix(svc.NetworkMode, "service:") {
		target := strings.TrimPrefix(svc.NetworkMode, "service:")
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "netns_container_network",
			Severity:    "high",
			Detail:      fmt.Sprintf("Service shares network namespace with service '%s' — network traffic visible across containers", target),
			Remediation: "Use separate bridge networks unless network sharing is required between these services",
		})
	}

	if svc.NetworkMode == "none" {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "netns_no_network",
			Severity:    "medium",
			Detail:      "Service has network_mode: none — completely isolated from network (verify this is intentional)",
			Remediation: "Confirm network isolation is intended; services requiring communication need a bridge network",
		})
	}

	return sr
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Network Namespace Isolation Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Total services:       %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Host network:         %d\n", r.Summary.HostNetwork)
	fmt.Fprintf(&b, "  Container sharing:    %d\n", r.Summary.ContainerNetwork)
	fmt.Fprintf(&b, "  No network:           %d\n", r.Summary.NoNetwork)
	fmt.Fprintf(&b, "  Total findings:       %d\n\n", r.Summary.TotalFindings)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s (%s)\n", s.Name, s.File)
		if s.NetworkMode != "" {
			fmt.Fprintf(&b, "    Network mode: %s\n", s.NetworkMode)
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Detail)
			fmt.Fprintf(&b, "      Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
