package egress

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

type ServiceEgress struct {
	Service          string   `json:"service"`
	NetworkMode      string   `json:"network_mode"`
	PublishedPorts   []int    `json:"published_ports"`
	AllInterfaces    bool     `json:"all_interfaces"`
	CustomDNS        bool     `json:"custom_dns"`
	DNSServers       []string `json:"dns_servers,omitempty"`
	ExposedInDocker  []string `json:"exposed_in_dockerfile,omitempty"`
	EgressRisk       string   `json:"egress_risk"`
}

type Summary struct {
	TotalServices     int `json:"total_services"`
	HostNetworkCount  int `json:"host_network_count"`
	WideOpenPorts     int `json:"wide_open_ports"`
	CustomDNSCount    int `json:"custom_dns_count"`
	HighRiskServices  int `json:"high_risk_services"`
	TotalFindings     int `json:"total_findings"`
	Score             int `json:"score"`
}

type Report struct {
	Services []ServiceEgress `json:"services"`
	Findings []Finding       `json:"findings"`
	Summary  Summary         `json:"summary"`
}

var sensitiveAgentPorts = map[int]string{
	80:    "HTTP",
	443:   "HTTPS",
	8080:  "HTTP-alt",
	8443:  "HTTPS-alt",
	3000:  "dev-server",
	5000:  "dev-server",
	9090:  "metrics",
	11434: "Ollama",
	8888:  "Jupyter",
}

func Analyze(collected *collect.Collected) Report {
	var services []ServiceEgress
	var findings []Finding

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			se, fs := analyzeService(cf.Path, svc)
			services = append(services, se)
			findings = append(findings, fs...)
		}
	}

	for _, df := range collected.Dockerfiles {
		findings = append(findings, analyzeDockerfileExpose(df)...)
	}

	hostNet, widePorts, customDNS, highRisk := 0, 0, 0, 0
	for _, se := range services {
		if se.NetworkMode == "host" {
			hostNet++
		}
		if se.AllInterfaces {
			widePorts += len(se.PublishedPorts)
		}
		if se.CustomDNS {
			customDNS++
		}
		if se.EgressRisk == "high" {
			highRisk++
		}
	}

	score := 100
	if len(services) > 0 {
		score -= hostNet * 20
		score -= widePorts * 5
		score -= customDNS * 10
		if score < 0 {
			score = 0
		}
	}

	return Report{
		Services: services,
		Findings: findings,
		Summary: Summary{
			TotalServices:    len(services),
			HostNetworkCount: hostNet,
			WideOpenPorts:    widePorts,
			CustomDNSCount:   customDNS,
			HighRiskServices: highRisk,
			TotalFindings:    len(findings),
			Score:            score,
		},
	}
}

func analyzeService(file string, svc compose.Service) (ServiceEgress, []Finding) {
	se := ServiceEgress{
		Service:     svc.Name,
		NetworkMode: svc.NetworkMode,
	}
	var findings []Finding

	if svc.NetworkMode == "host" {
		se.EgressRisk = "high"
		findings = append(findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "egress_host_network",
			Severity:    "high",
			Detail:      fmt.Sprintf("service %q uses network_mode: host — full host network access", svc.Name),
			Remediation: "Use a bridge network with explicit port mappings to limit egress",
		})
	}

	for _, pm := range svc.Ports {
		se.PublishedPorts = append(se.PublishedPorts, pm.TargetPort)
		if pm.IsAllInterfaces() {
			se.AllInterfaces = true
			sev := "medium"
			if desc, ok := sensitiveAgentPorts[pm.TargetPort]; ok {
				sev = "high"
				findings = append(findings, Finding{
					Service:     svc.Name,
					File:        file,
					RuleID:      "egress_sensitive_port_exposed",
					Severity:    sev,
					Detail:      fmt.Sprintf("service %q exposes %s port %d on all interfaces", svc.Name, desc, pm.TargetPort),
					Remediation: fmt.Sprintf("Bind port %d to 127.0.0.1 unless external access is intended", pm.TargetPort),
				})
			} else {
				findings = append(findings, Finding{
					Service:     svc.Name,
					File:        file,
					RuleID:      "egress_port_all_interfaces",
					Severity:    sev,
					Detail:      fmt.Sprintf("service %q publishes port %d on 0.0.0.0 (all interfaces)", svc.Name, pm.TargetPort),
					Remediation: fmt.Sprintf("Bind to 127.0.0.1:%d:%d to restrict to localhost", pm.HostPort, pm.TargetPort),
				})
			}
		}
	}

	if len(svc.DNS) > 0 {
		se.CustomDNS = true
		se.DNSServers = svc.DNS
		external := false
		for _, dns := range svc.DNS {
			if !strings.HasPrefix(dns, "127.") && dns != "::1" {
				external = true
			}
		}
		if external {
			findings = append(findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "egress_custom_dns",
				Severity:    "medium",
				Detail:      fmt.Sprintf("service %q uses custom DNS servers %v — may bypass network policies", svc.Name, svc.DNS),
				Remediation: "Use the default DNS or a controlled internal resolver",
			})
		}
	}

	if se.EgressRisk == "" {
		if se.AllInterfaces && len(se.PublishedPorts) > 3 {
			se.EgressRisk = "high"
		} else if se.AllInterfaces || se.CustomDNS {
			se.EgressRisk = "medium"
		} else {
			se.EgressRisk = "low"
		}
	}

	return se, findings
}

func analyzeDockerfileExpose(df collect.Dockerfile) []Finding {
	var findings []Finding
	for _, exp := range df.Exposes {
		ports := strings.Fields(exp.Ports)
		for _, p := range ports {
			p = strings.TrimSuffix(p, "/tcp")
			p = strings.TrimSuffix(p, "/udp")
			for port, desc := range sensitiveAgentPorts {
				if p == fmt.Sprintf("%d", port) {
					findings = append(findings, Finding{
						File:        df.Path,
						RuleID:      "egress_dockerfile_expose_sensitive",
						Severity:    "low",
						Detail:      fmt.Sprintf("Dockerfile exposes %s port %s (line %d)", desc, p, exp.Line),
						Remediation: "Ensure this port is not published to all interfaces at runtime",
					})
				}
			}
		}
	}
	return findings
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Network Egress Security Audit\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	fmt.Fprintf(&sb, "  Services Analyzed:    %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&sb, "  Host Network:         %d\n", r.Summary.HostNetworkCount)
	fmt.Fprintf(&sb, "  Wide-Open Ports:      %d\n", r.Summary.WideOpenPorts)
	fmt.Fprintf(&sb, "  Custom DNS:           %d\n", r.Summary.CustomDNSCount)
	fmt.Fprintf(&sb, "  High-Risk Services:   %d\n", r.Summary.HighRiskServices)
	fmt.Fprintf(&sb, "  Egress Score:         %d/100\n\n", r.Summary.Score)

	if len(r.Services) > 0 {
		sb.WriteString("Services:\n")
		for _, se := range r.Services {
			fmt.Fprintf(&sb, "  - %s (risk=%s, network=%s, ports=%v)\n",
				se.Service, se.EgressRisk, se.NetworkMode, se.PublishedPorts)
		}
		sb.WriteString("\n")
	}

	if len(r.Findings) > 0 {
		sb.WriteString("Findings:\n")
		for i, f := range r.Findings {
			fmt.Fprintf(&sb, "  %d. [%s] %s (%s)\n", i+1, f.Severity, f.Detail, f.RuleID)
			fmt.Fprintf(&sb, "     Fix: %s\n", f.Remediation)
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
