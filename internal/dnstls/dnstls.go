package dnstls

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
	TotalServices          int `json:"total_services"`
	TotalFindings          int `json:"total_findings"`
	PlaintextDNS           int `json:"plaintext_dns"`
	PublicDNSResolver      int `json:"public_dns_resolver"`
	MissingDNSConfig       int `json:"missing_dns_config"`
	DNSOverTLSAvailable    int `json:"dns_over_tls_available"`
	InsecureDNSWithSecrets int `json:"insecure_dns_with_secrets"`
}

var publicDNSResolvers = []string{
	"8.8.8.8", "8.8.4.4",
	"1.1.1.1", "1.0.0.1",
	"9.9.9.9", "149.112.112.112",
	"208.67.222.222", "208.67.220.220",
	"76.76.2.0", "76.76.10.0",
}

var dnsOverTLSImages = []string{
	"cloudflare/cloudflared", "pihole", "adguard",
	"unbound", "coredns", "dnscrypt",
	"stubby", "knot-resolver",
}

var sensitiveImages = []string{
	"vault", "keycloak", "postgres", "mysql", "mongo",
	"redis", "rabbitmq", "kafka", "elasticsearch", "minio",
}

func isPublicDNS(addr string) bool {
	trimmed := strings.TrimSpace(addr)
	for _, r := range publicDNSResolvers {
		if trimmed == r {
			return true
		}
	}
	return false
}

func isDNSOverTLSImage(image string) bool {
	lower := strings.ToLower(image)
	for _, d := range dnsOverTLSImages {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

func isSensitiveImage(image string) bool {
	lower := strings.ToLower(image)
	for _, s := range sensitiveImages {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func hasDNSOverTLSEnv(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "dns_over_tls") ||
			strings.Contains(lower, "dot_server") ||
			strings.Contains(lower, "dns_tls") ||
			strings.Contains(lower, "doh_server") ||
			strings.Contains(lower, "dns_over_https") ||
			strings.Contains(lower, "tls_upstream") {
			return true
		}
	}
	return false
}

func hasDNSPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if p.TargetPort == 53 || p.TargetPort == 853 || p.TargetPort == 5353 {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string, hasDOTResolver bool) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	hasPlaintextDNS := false
	hasPublicResolver := false

	for _, d := range svc.DNS {
		if isPublicDNS(d) {
			hasPublicResolver = true
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "public_dns_resolver",
				Message: fmt.Sprintf("Service '%s' uses public DNS resolver %s; DNS queries are sent in plaintext and can be monitored or tampered with by network intermediaries", svc.Name, d),
			})
		}
		hasPlaintextDNS = true
	}

	if hasPlaintextDNS && !hasDNSOverTLSEnv(svc) && !hasDOTResolver {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "plaintext_dns",
			Message: fmt.Sprintf("Service '%s' uses plaintext DNS without DNS-over-TLS or DNS-over-HTTPS; DNS queries expose the domains this service communicates with", svc.Name),
		})
	}

	if len(svc.DNS) == 0 && !hasDOTResolver && svc.NetworkMode != "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "missing_dns_config",
			Message: fmt.Sprintf("Service '%s' has no explicit DNS configuration; it relies on the Docker daemon's default resolver which may not support encrypted DNS", svc.Name),
		})
	}

	if isDNSOverTLSImage(svc.Image) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "dns_over_tls_available",
			Message: fmt.Sprintf("Service '%s' runs a DNS resolver that supports DNS-over-TLS/HTTPS; ensure upstream queries use encrypted transport", svc.Name),
		})
	}

	if isSensitiveImage(svc.Image) && hasPublicResolver && !hasDNSOverTLSEnv(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "insecure_dns_with_secrets",
			Message: fmt.Sprintf("Sensitive service '%s' uses a public DNS resolver without encryption; DNS queries may reveal which external services this database/secret store communicates with", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		hasDOTResolver := false
		for _, svc := range cf.Services {
			if isDNSOverTLSImage(svc.Image) && hasDNSPort(svc) {
				hasDOTResolver = true
				break
			}
		}
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, hasDOTResolver)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "plaintext_dns":
				s.PlaintextDNS++
			case "public_dns_resolver":
				s.PublicDNSResolver++
			case "missing_dns_config":
				s.MissingDNSConfig++
			case "dns_over_tls_available":
				s.DNSOverTLSAvailable++
			case "insecure_dns_with_secrets":
				s.InsecureDNSWithSecrets++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "DNS-over-TLS Security Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Plaintext DNS:                 %d\n", r.Summary.PlaintextDNS)
	fmt.Fprintf(&b, "  Public DNS resolvers:          %d\n", r.Summary.PublicDNSResolver)
	fmt.Fprintf(&b, "  Missing DNS config:            %d\n", r.Summary.MissingDNSConfig)
	fmt.Fprintf(&b, "  DNS-over-TLS available:        %d\n", r.Summary.DNSOverTLSAvailable)
	fmt.Fprintf(&b, "  Insecure DNS with secrets:     %d\n\n", r.Summary.InsecureDNSWithSecrets)
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
