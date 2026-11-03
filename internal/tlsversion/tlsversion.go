package tlsversion

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
	TotalServices       int `json:"total_services"`
	TotalFindings       int `json:"total_findings"`
	WeakTLSVersion      int `json:"weak_tls_version"`
	SSLv3Enabled        int `json:"sslv3_enabled"`
	MissingMinVersion   int `json:"missing_min_version"`
	WeakCipherSuite     int `json:"weak_cipher_suite"`
	TLSNotEnforced      int `json:"tls_not_enforced"`
}

var tlsAwareImages = []string{
	"nginx", "haproxy", "traefik", "envoyproxy/envoy", "caddy",
	"apache", "httpd", "openresty", "kong", "istio",
	"postgres", "mysql", "mariadb", "redis", "mongo",
	"rabbitmq", "nats", "mosquitto", "consul", "vault",
}

var weakSSLVersions = []string{
	"sslv2", "sslv3", "ssl2", "ssl3",
}

var weakTLSVersions = []string{
	"tlsv1.0", "tls1.0", "tls_1_0",
	"tlsv1.1", "tls1.1", "tls_1_1",
}

var weakCiphers = []string{
	"rc4", "des", "3des", "md5", "null",
	"export", "anon", "adh", "aecdh",
	"rc2", "idea", "seed", "camellia128",
}

func isTLSAware(svc compose.Service) bool {
	lower := strings.ToLower(svc.Image)
	for _, img := range tlsAwareImages {
		if strings.Contains(lower, img) {
			return true
		}
	}
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "tls") || strings.Contains(lower, "ssl") ||
			strings.Contains(lower, "https") || strings.Contains(lower, "cert") {
			return true
		}
	}
	return false
}

func hasPublicPorts(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if p.IsAllInterfaces() {
			return true
		}
	}
	return false
}

func hasTLSConfig(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "tls_") || strings.Contains(lower, "ssl_") ||
			strings.Contains(lower, "_tls") || strings.Contains(lower, "_ssl") ||
			strings.Contains(lower, "https") || strings.Contains(lower, "ssl=") {
			return true
		}
	}
	return false
}

func hasMinVersionConfig(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "min_version") || strings.Contains(lower, "min_tls") ||
			strings.Contains(lower, "tls_min") || strings.Contains(lower, "ssl_min") ||
			strings.Contains(lower, "min_protocol") || strings.Contains(lower, "protocol_min") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isTLSAware(svc) {
		return sr
	}

	for _, e := range svc.Environment {
		lower := strings.ToLower(e)

		sslFound := false
		for _, wv := range weakSSLVersions {
			if strings.Contains(lower, wv) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "critical",
					Rule:    "sslv3_enabled",
					Message: fmt.Sprintf("Service '%s' references deprecated SSL version '%s'; SSLv2/v3 have known vulnerabilities (POODLE, DROWN) and must not be used", svc.Name, wv),
				})
				sslFound = true
				break
			}
		}

		if !sslFound {
			for _, wv := range weakTLSVersions {
				if strings.Contains(lower, wv) {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "high",
						Rule:    "weak_tls_version",
						Message: fmt.Sprintf("Service '%s' references weak TLS version '%s'; TLS 1.0/1.1 are deprecated (RFC 8996) and vulnerable to BEAST/CRIME attacks", svc.Name, wv),
					})
					break
				}
			}
		}

		for _, wc := range weakCiphers {
			if strings.Contains(lower, "cipher") && strings.Contains(lower, wc) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "weak_cipher_suite",
					Message: fmt.Sprintf("Service '%s' references weak cipher '%s'; weak ciphers allow decryption of intercepted traffic", svc.Name, wc),
				})
				break
			}
		}
	}

	if hasTLSConfig(svc) && !hasMinVersionConfig(svc) && hasPublicPorts(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "missing_min_version",
			Message: fmt.Sprintf("Service '%s' has TLS configuration but no minimum version specified; without a floor, clients may negotiate deprecated protocol versions", svc.Name),
		})
	}

	if hasPublicPorts(svc) && !hasTLSConfig(svc) && isTLSAware(svc) {
		for _, p := range svc.Ports {
			if p.IsAllInterfaces() && (p.TargetPort == 80 || p.TargetPort == 8080 || p.TargetPort == 5432 || p.TargetPort == 3306 || p.TargetPort == 6379 || p.TargetPort == 27017) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "tls_not_enforced",
					Message: fmt.Sprintf("Service '%s' exposes port %d publicly without TLS configuration; traffic on this port may be transmitted in cleartext", svc.Name, p.TargetPort),
				})
				break
			}
		}
	}

	return sr
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

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "weak_tls_version":
				s.WeakTLSVersion++
			case "sslv3_enabled":
				s.SSLv3Enabled++
			case "missing_min_version":
				s.MissingMinVersion++
			case "weak_cipher_suite":
				s.WeakCipherSuite++
			case "tls_not_enforced":
				s.TLSNotEnforced++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "TLS Version Security Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Weak TLS version:            %d\n", r.Summary.WeakTLSVersion)
	fmt.Fprintf(&b, "  SSLv2/v3 enabled:            %d\n", r.Summary.SSLv3Enabled)
	fmt.Fprintf(&b, "  Missing min version:         %d\n", r.Summary.MissingMinVersion)
	fmt.Fprintf(&b, "  Weak cipher suite:           %d\n", r.Summary.WeakCipherSuite)
	fmt.Fprintf(&b, "  TLS not enforced:            %d\n\n", r.Summary.TLSNotEnforced)
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
