package apiexpose

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
	TotalServices    int `json:"total_services"`
	TotalFindings    int `json:"total_findings"`
	DockerAPI        int `json:"docker_api"`
	DebugPort        int `json:"debug_port"`
	WildcardBind     int `json:"wildcard_bind"`
	MgmtPort         int `json:"mgmt_port"`
	PrivilegedPort   int `json:"privileged_port"`
	HostNetworkPorts int `json:"host_network_ports"`
}

var dockerAPIPorts = map[int]bool{2375: true, 2376: true}

var debugPorts = map[int]string{
	9229: "Node.js inspector",
	5005: "Java JDWP debug",
	4000: "Go Delve debugger",
	2345: "Go Delve debugger (alt)",
	5858: "Node.js legacy debug",
	8787: "R debug",
}

var mgmtPorts = map[int]string{
	9000: "Portainer/management UI",
	8080: "cAdvisor/admin",
	9090: "Prometheus",
	3000: "Grafana",
	5601: "Kibana",
	15672: "RabbitMQ management",
	8500: "Consul UI",
	8200: "Vault UI",
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	isHostNet := strings.EqualFold(svc.NetworkMode, "host")

	if isHostNet && len(svc.Ports) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "apiexpose_host_network_ports",
			Message: fmt.Sprintf("Service '%s' uses network_mode:host with port mappings; ports directive is ignored in host mode", svc.Name),
		})
	}

	for _, p := range svc.Ports {
		if dockerAPIPorts[p.HostPort] || dockerAPIPorts[p.TargetPort] {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "apiexpose_docker_api",
				Message: fmt.Sprintf("Service '%s' exposes Docker API port %s; grants full daemon control", svc.Name, p.Raw),
			})
			continue
		}

		if desc, ok := debugPorts[p.TargetPort]; ok {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "apiexpose_debug_port",
				Message: fmt.Sprintf("Service '%s' exposes %s port %s; allows remote code execution", svc.Name, desc, p.Raw),
			})
		}

		if desc, ok := mgmtPorts[p.TargetPort]; ok {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "apiexpose_mgmt_port",
				Message: fmt.Sprintf("Service '%s' exposes %s port %s; restrict to internal network", svc.Name, desc, p.Raw),
			})
		}

		if p.HostPort > 0 && p.HostPort < 1024 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "apiexpose_privileged_port",
				Message: fmt.Sprintf("Service '%s' binds privileged host port %d (%s); requires root on host", svc.Name, p.HostPort, p.Raw),
			})
		}

		if p.HostIP == "" || p.HostIP == "0.0.0.0" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "apiexpose_wildcard_bind",
				Message: fmt.Sprintf("Service '%s' binds port %s to all interfaces; consider 127.0.0.1 binding", svc.Name, p.Raw),
			})
		}
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "apiexpose_docker_api":
				s.DockerAPI++
			case "apiexpose_debug_port":
				s.DebugPort++
			case "apiexpose_wildcard_bind":
				s.WildcardBind++
			case "apiexpose_mgmt_port":
				s.MgmtPort++
			case "apiexpose_privileged_port":
				s.PrivilegedPort++
			case "apiexpose_host_network_ports":
				s.HostNetworkPorts++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "API Exposure Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Docker API exposed:     %d\n", r.Summary.DockerAPI)
	fmt.Fprintf(&b, "  Debug ports exposed:    %d\n", r.Summary.DebugPort)
	fmt.Fprintf(&b, "  Wildcard bindings:      %d\n", r.Summary.WildcardBind)
	fmt.Fprintf(&b, "  Management ports:       %d\n", r.Summary.MgmtPort)
	fmt.Fprintf(&b, "  Privileged ports:       %d\n", r.Summary.PrivilegedPort)
	fmt.Fprintf(&b, "  Host network + ports:   %d\n\n", r.Summary.HostNetworkPorts)
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
