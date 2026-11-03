package netfilter

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type ServiceResult struct {
	Service  string    `json:"service"`
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices      int `json:"total_services"`
	TotalFindings      int `json:"total_findings"`
	UnrestrictedPorts  int `json:"unrestricted_ports"`
	HostNetworks       int `json:"host_networks"`
	NoEgressControl    int `json:"no_egress_control"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}

	hasNetworks := false
	for _, cf := range c.ComposeFiles {
		if len(cf.Networks) > 0 {
			hasNetworks = true
			break
		}
	}

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, hasNetworks, c)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string, hasNetworks bool, c *collect.Collected) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if svc.NetworkMode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "netfilter_host_network",
			Message: fmt.Sprintf("Service '%s' uses network_mode: host; this bypasses Docker network isolation and exposes all host ports", svc.Name),
		})
	}

	if len(svc.Ports) > 0 && !hasNetworks && svc.NetworkMode != "host" {
		portList := formatPorts(svc.Ports)
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "netfilter_unrestricted_ports",
			Message: fmt.Sprintf("Service '%s' exposes ports %s without network restrictions; no custom networks defined in compose file", svc.Name, portList),
		})
	}

	if isAgentService(svc, c) && svc.NetworkMode != "none" && !hasEgressRestriction(svc, c) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "netfilter_no_egress_control",
			Message: fmt.Sprintf("Service '%s' appears to be an AI agent container with no egress controls; consider using network_mode: none or a restricted network", svc.Name),
		})
	}

	return sr
}

func formatPorts(ports []compose.PortMapping) string {
	var parts []string
	for _, p := range ports {
		if p.Raw != "" {
			parts = append(parts, p.Raw)
		} else if p.HostPort != 0 {
			parts = append(parts, fmt.Sprintf("%d:%d", p.HostPort, p.TargetPort))
		} else {
			parts = append(parts, fmt.Sprintf("%d", p.TargetPort))
		}
	}
	return strings.Join(parts, ", ")
}

func isAgentService(svc compose.Service, c *collect.Collected) bool {
	lower := strings.ToLower(svc.Image)
	agentKeywords := []string{"agent", "langchain", "autogen", "crewai", "opendevin", "openhands", "flowise", "n8n", "dify", "langflow"}
	for _, kw := range agentKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	nameLower := strings.ToLower(svc.Name)
	for _, kw := range agentKeywords {
		if strings.Contains(nameLower, kw) {
			return true
		}
	}
	for _, rt := range c.DetectedAgentRuntimes {
		if strings.EqualFold(rt, svc.Name) || strings.Contains(strings.ToLower(svc.Image), strings.ToLower(rt)) {
			return true
		}
	}
	return false
}

func hasEgressRestriction(svc compose.Service, c *collect.Collected) bool {
	if svc.NetworkMode == "none" {
		return true
	}
	if c.HasNetworkPolicy {
		return true
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "netfilter_unrestricted_ports":
				s.UnrestrictedPorts++
			case "netfilter_host_network":
				s.HostNetworks++
			case "netfilter_no_egress_control":
				s.NoEgressControl++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Network Filtering Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Unrestricted ports:   %d\n", r.Summary.UnrestrictedPorts)
	fmt.Fprintf(&b, "  Host network mode:    %d\n", r.Summary.HostNetworks)
	fmt.Fprintf(&b, "  No egress control:    %d\n\n", r.Summary.NoEgressControl)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s\n", sr.Service)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		if len(sr.Findings) == 0 {
			fmt.Fprintf(&b, "    (no findings)\n")
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
