package dnsleak

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
	TotalServices     int `json:"total_services"`
	TotalFindings     int `json:"total_findings"`
	PublicDNS         int `json:"public_dns"`
	NoDNSConfig       int `json:"no_dns_config"`
	HostNetwork       int `json:"host_network"`
	WildcardSearch    int `json:"wildcard_search"`
	MismatchedDNS     int `json:"mismatched_dns"`
}

var publicDNSServers = map[string]bool{
	"8.8.8.8":         true,
	"8.8.4.4":         true,
	"1.1.1.1":         true,
	"1.0.0.1":         true,
	"208.67.222.222":  true,
	"208.67.220.220":  true,
	"9.9.9.9":         true,
	"149.112.112.112": true,
	"64.6.64.6":       true,
	"64.6.65.6":       true,
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	allDNS := collectDNSConfigs(c)
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, allDNS)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func collectDNSConfigs(c *collect.Collected) map[string][]string {
	configs := map[string][]string{}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if len(svc.DNS) > 0 {
				configs[svc.Name] = svc.DNS
			}
		}
	}
	return configs
}

func analyzeService(svc compose.Service, file string, allDNS map[string][]string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if strings.ToLower(svc.NetworkMode) == "host" && len(svc.DNS) == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "dnsleak_host_network",
			Message: fmt.Sprintf("Service '%s' uses host network mode without custom DNS; inherits host DNS resolvers that may leak queries", svc.Name),
		})
	}

	if len(svc.DNS) == 0 && svc.NetworkMode == "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "dnsleak_no_dns_config",
			Message: fmt.Sprintf("Service '%s' has no explicit DNS configuration; relies on Docker's default resolver", svc.Name),
		})
	}

	for _, dns := range svc.DNS {
		ip := strings.TrimSpace(dns)
		if publicDNSServers[ip] {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "dnsleak_public_dns",
				Message: fmt.Sprintf("Service '%s' uses public DNS resolver %s; internal queries may leak to third-party infrastructure", svc.Name, ip),
			})
		}
		if parsed := net.ParseIP(ip); parsed == nil && ip != "" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "dnsleak_invalid_dns",
				Message: fmt.Sprintf("Service '%s' has invalid DNS entry '%s'", svc.Name, ip),
			})
		}
	}

	for _, search := range svc.DNSSearch {
		s := strings.TrimSpace(search)
		if s == "." || s == "" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "dnsleak_wildcard_search",
				Message: fmt.Sprintf("Service '%s' uses wildcard DNS search domain '.'; queries for short names will try the root domain", svc.Name),
			})
		}
	}

	if len(allDNS) > 1 && len(svc.DNS) > 0 {
		for otherSvc, otherDNS := range allDNS {
			if otherSvc == svc.Name {
				continue
			}
			if !dnsEqual(svc.DNS, otherDNS) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "low",
					Rule:    "dnsleak_mismatched_dns",
					Message: fmt.Sprintf("Service '%s' has different DNS config than '%s'; inconsistent resolution may cause split-horizon issues", svc.Name, otherSvc),
				})
				break
			}
		}
	}

	return sr
}

func dnsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.TrimSpace(a[i]) != strings.TrimSpace(b[i]) {
			return false
		}
	}
	return true
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "dnsleak_public_dns":
				s.PublicDNS++
			case "dnsleak_no_dns_config":
				s.NoDNSConfig++
			case "dnsleak_host_network":
				s.HostNetwork++
			case "dnsleak_wildcard_search":
				s.WildcardSearch++
			case "dnsleak_mismatched_dns":
				s.MismatchedDNS++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "DNS Leak Risk Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Public DNS resolvers:   %d\n", r.Summary.PublicDNS)
	fmt.Fprintf(&b, "  No DNS config:          %d\n", r.Summary.NoDNSConfig)
	fmt.Fprintf(&b, "  Host network DNS leak:  %d\n", r.Summary.HostNetwork)
	fmt.Fprintf(&b, "  Wildcard search domain: %d\n", r.Summary.WildcardSearch)
	fmt.Fprintf(&b, "  Mismatched DNS:         %d\n\n", r.Summary.MismatchedDNS)
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
