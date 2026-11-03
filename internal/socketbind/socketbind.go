package socketbind

import (
	"fmt"
	"regexp"
	"strconv"
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
	WildcardBind       int `json:"wildcard_bind"`
	PrivilegedPort     int `json:"privileged_port"`
	ExposedDebugPort   int `json:"exposed_debug_port"`
	UDPExposed         int `json:"udp_exposed"`
	HostNetBind        int `json:"host_net_bind"`
	MissingHostMapping int `json:"missing_host_mapping"`
}

var wildcardBindPatterns = []string{
	"0.0.0.0", "[::]", "inaddr_any",
}

var debugPortNumbers = []int{
	5005, 5858, 9229, 9230, 4200, 8787, 40000, 2345, 1234,
}

var portRegex = regexp.MustCompile(`(\d+):(\d+)(/udp)?`)
var listenRegex = regexp.MustCompile(`(?i)(?:listen|bind|host)\s*[=:]\s*([^\s,]+)`)
var portEnvRegex = regexp.MustCompile(`(?i)(?:port|listen_port|bind_port)\s*=\s*(\d+)`)

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

	checkPortMappings(&sr, svc)
	checkBindAddress(&sr, svc)
	checkHostNetwork(&sr, svc)

	return sr
}

func checkPortMappings(sr *ServiceResult, svc compose.Service) {
	for _, p := range svc.Ports {
		hostPort := p.HostPort
		containerPort := p.TargetPort
		isUDP := strings.HasSuffix(p.Raw, "/udp")

		if hostPort > 0 && hostPort < 1024 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "socket_privileged_port",
				Message: fmt.Sprintf("Service '%s' binds to privileged port %d; requires elevated privileges and increases attack surface", svc.Name, hostPort),
			})
		}

		if isDebugPort(containerPort) || isDebugPort(hostPort) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "socket_debug_port",
				Message: fmt.Sprintf("Service '%s' exposes debug port %d; remote code execution risk if debugger is active", svc.Name, containerPort),
			})
		}

		if isUDP {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "socket_udp_exposed",
				Message: fmt.Sprintf("Service '%s' exposes UDP port %d; UDP services are harder to firewall and susceptible to amplification attacks", svc.Name, containerPort),
			})
		}

		if hostPort == 0 && containerPort > 0 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "socket_missing_host_mapping",
				Message: fmt.Sprintf("Service '%s' exposes container port %d without explicit host port mapping; binding behavior is host-dependent", svc.Name, containerPort),
			})
		}
	}
}

func checkBindAddress(sr *ServiceResult, svc compose.Service) {
	sources := gatherText(svc)
	joined := strings.Join(sources, " ")
	lower := strings.ToLower(joined)

	for _, pattern := range wildcardBindPatterns {
		if strings.Contains(lower, pattern) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "socket_wildcard_bind",
				Message: fmt.Sprintf("Service '%s' binds to all interfaces (%s); should bind to 127.0.0.1 or specific interface for least privilege", svc.Name, pattern),
			})
			break
		}
	}

	matches := listenRegex.FindAllStringSubmatch(joined, -1)
	for _, m := range matches {
		addr := m[1]
		if strings.Contains(addr, "0.0.0.0") || strings.Contains(addr, "[::]") {
			continue
		}
	}
	_ = matches

	envMatches := portEnvRegex.FindAllStringSubmatch(joined, -1)
	for _, m := range envMatches {
		port, _ := strconv.Atoi(m[1])
		if port > 0 && port < 1024 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "socket_privileged_port",
				Message: fmt.Sprintf("Service '%s' configures privileged port %d via environment; requires elevated privileges", svc.Name, port),
			})
		}
	}
}

func checkHostNetwork(sr *ServiceResult, svc compose.Service) {
	if svc.NetworkMode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "socket_host_net_bind",
			Message: fmt.Sprintf("Service '%s' uses host network mode; all socket bindings are directly on the host interface with no network isolation", svc.Name),
		})
	}
}

func gatherText(svc compose.Service) []string {
	var parts []string
	parts = append(parts, svc.Entrypoint...)
	parts = append(parts, svc.Command...)
	parts = append(parts, svc.Environment...)
	for k, v := range svc.Labels {
		parts = append(parts, k+"="+v)
	}
	return parts
}

func isDebugPort(port int) bool {
	for _, dp := range debugPortNumbers {
		if port == dp {
			return true
		}
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "socket_wildcard_bind":
				s.WildcardBind++
			case "socket_privileged_port":
				s.PrivilegedPort++
			case "socket_debug_port":
				s.ExposedDebugPort++
			case "socket_udp_exposed":
				s.UDPExposed++
			case "socket_host_net_bind":
				s.HostNetBind++
			case "socket_missing_host_mapping":
				s.MissingHostMapping++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Socket Binding Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Wildcard bind (0.0.0.0):  %d\n", r.Summary.WildcardBind)
	fmt.Fprintf(&b, "  Privileged port (<1024):  %d\n", r.Summary.PrivilegedPort)
	fmt.Fprintf(&b, "  Exposed debug port:       %d\n", r.Summary.ExposedDebugPort)
	fmt.Fprintf(&b, "  UDP exposed:              %d\n", r.Summary.UDPExposed)
	fmt.Fprintf(&b, "  Host network bind:        %d\n", r.Summary.HostNetBind)
	fmt.Fprintf(&b, "  Missing host mapping:     %d\n\n", r.Summary.MissingHostMapping)
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
