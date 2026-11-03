package linklocal

import (
	"encoding/json"
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
	TotalServices       int `json:"total_services"`
	TotalFindings       int `json:"total_findings"`
	LinkLocalBound      int `json:"link_local_bound"`
	WildcardBound       int `json:"wildcard_bound"`
	LoopbackOnly        int `json:"loopback_only"`
	MulticastDNS        int `json:"multicast_dns"`
}

func isLinkLocal(ip string) bool {
	return strings.HasPrefix(ip, "169.254.") || strings.HasPrefix(ip, "fe80:")
}

func isWildcard(ip string) bool {
	return ip == "" || ip == "0.0.0.0" || ip == "::"
}

func isLoopback(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
}

func isMulticastDNSPort(port int) bool {
	return port == 5353
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

	loopbackCount := 0
	wildcardCount := 0

	for _, pm := range svc.Ports {
		if isLinkLocal(pm.HostIP) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "link_local_bind",
				Message: fmt.Sprintf("Service '%s' binds port %d to link-local address %s; link-local addresses are reachable from the local network segment and may expose the service unintentionally", svc.Name, pm.TargetPort, pm.HostIP),
			})
		}

		if isWildcard(pm.HostIP) {
			wildcardCount++
		}
		if isLoopback(pm.HostIP) {
			loopbackCount++
		}

		if isMulticastDNSPort(pm.HostPort) || isMulticastDNSPort(pm.TargetPort) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "multicast_dns_port",
				Message: fmt.Sprintf("Service '%s' exposes mDNS port 5353; multicast DNS can leak service discovery information to the local network", svc.Name),
			})
		}
	}

	if wildcardCount > 0 && len(svc.Ports) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "wildcard_bind",
			Message: fmt.Sprintf("Service '%s' binds %d port(s) to all interfaces (0.0.0.0); consider binding to 127.0.0.1 for local-only services", svc.Name, wildcardCount),
		})
	}

	if loopbackCount > 0 && loopbackCount == len(svc.Ports) && len(svc.Ports) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "loopback_only",
			Message: fmt.Sprintf("Service '%s' binds all %d port(s) to loopback only; good practice for local-only services", svc.Name, loopbackCount),
		})
	}

	for _, dns := range svc.DNS {
		if isLinkLocal(dns) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "link_local_dns",
				Message: fmt.Sprintf("Service '%s' uses link-local DNS server %s; link-local DNS can be spoofed from the local network segment", svc.Name, dns),
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
			case "link_local_bind", "link_local_dns":
				s.LinkLocalBound++
			case "wildcard_bind":
				s.WildcardBound++
			case "loopback_only":
				s.LoopbackOnly++
			case "multicast_dns_port":
				s.MulticastDNS++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Link-Local & Network Binding Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Link-local bindings:   %d\n", r.Summary.LinkLocalBound)
	fmt.Fprintf(&b, "  Wildcard bindings:     %d\n", r.Summary.WildcardBound)
	fmt.Fprintf(&b, "  Loopback-only:         %d\n", r.Summary.LoopbackOnly)
	fmt.Fprintf(&b, "  Multicast DNS:         %d\n\n", r.Summary.MulticastDNS)
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

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
