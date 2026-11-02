package dnsrebind

import (
	"fmt"
	"net"
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
	HostNetNoDNS        int `json:"host_net_no_dns"`
	PublicDNSInPrivate   int `json:"public_dns_in_private"`
	WildcardDNSSearch   int `json:"wildcard_dns_search"`
	NoDNSRestriction    int `json:"no_dns_restriction"`
}

var publicDNSServers = map[string]bool{
	"8.8.8.8":         true,
	"8.8.4.4":         true,
	"1.1.1.1":         true,
	"1.0.0.1":         true,
	"9.9.9.9":         true,
	"208.67.222.222":  true,
	"208.67.220.220":  true,
	"64.6.64.6":       true,
	"64.6.65.6":       true,
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	privateNets := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
	for _, cidr := range privateNets {
		_, n, _ := net.ParseCIDR(cidr)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isPublicDNS(server string) bool {
	return publicDNSServers[strings.TrimSpace(server)]
}

func hasHostNetwork(svc compose.Service) bool {
	return svc.NetworkMode == "host"
}

func isInternalService(svc compose.Service) bool {
	lower := strings.ToLower(svc.Name)
	for _, kw := range []string{"internal", "backend", "db", "redis", "postgres", "mysql", "mongo", "cache"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	if len(svc.Ports) == 0 {
		return true
	}
	for _, p := range svc.Ports {
		if isPrivateIP(p.HostIP) {
			return true
		}
	}
	return false
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

	if hasHostNetwork(svc) && len(svc.DNS) == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "dnsrebind_host_net_no_dns",
			Message: fmt.Sprintf("Service '%s' uses host network without explicit DNS servers; host DNS resolution exposes to DNS rebinding attacks targeting internal services", svc.Name),
		})
	}

	if isInternalService(svc) {
		for _, d := range svc.DNS {
			if isPublicDNS(d) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "dnsrebind_public_dns_internal",
					Message: fmt.Sprintf("Service '%s' is internal but uses public DNS server '%s'; public resolvers can be exploited for DNS rebinding to reach internal endpoints", svc.Name, d),
				})
			}
		}
	}

	for _, ds := range svc.DNSSearch {
		trimmed := strings.TrimSpace(ds)
		if trimmed == "." || trimmed == "" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "dnsrebind_wildcard_search",
				Message: fmt.Sprintf("Service '%s' has wildcard DNS search domain '%s'; broad search domains increase DNS rebinding attack surface", svc.Name, ds),
			})
		}
	}

	if hasHostNetwork(svc) && len(svc.DNS) > 0 {
		allPublic := true
		for _, d := range svc.DNS {
			if !isPublicDNS(d) {
				allPublic = false
				break
			}
		}
		if allPublic {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "dnsrebind_host_all_public_dns",
				Message: fmt.Sprintf("Service '%s' uses host network with only public DNS servers; consider using a local resolver with rebinding protection", svc.Name),
			})
		}
	}

	if !hasHostNetwork(svc) && len(svc.DNS) == 0 && len(svc.DNSSearch) == 0 && len(svc.Ports) > 0 {
		hasExposedWebPort := false
		for _, p := range svc.Ports {
			port := p.TargetPort
			if port == 80 || port == 443 || port == 8080 || port == 8443 || port == 3000 || port == 5000 {
				hasExposedWebPort = true
				break
			}
		}
		if hasExposedWebPort {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "dnsrebind_web_no_dns_restrict",
				Message: fmt.Sprintf("Service '%s' exposes web ports without explicit DNS configuration; consider setting DNS servers to reduce rebinding risk", svc.Name),
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
			case "dnsrebind_host_net_no_dns":
				s.HostNetNoDNS++
			case "dnsrebind_public_dns_internal":
				s.PublicDNSInPrivate++
			case "dnsrebind_wildcard_search":
				s.WildcardDNSSearch++
			case "dnsrebind_web_no_dns_restrict":
				s.NoDNSRestriction++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "DNS Rebinding Protection Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Host net without DNS:   %d\n", r.Summary.HostNetNoDNS)
	fmt.Fprintf(&b, "  Public DNS (internal):  %d\n", r.Summary.PublicDNSInPrivate)
	fmt.Fprintf(&b, "  Wildcard DNS search:    %d\n", r.Summary.WildcardDNSSearch)
	fmt.Fprintf(&b, "  No DNS restriction:     %d\n\n", r.Summary.NoDNSRestriction)
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
