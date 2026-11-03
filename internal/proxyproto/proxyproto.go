package proxyproto

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
	TotalServices              int `json:"total_services"`
	TotalFindings              int `json:"total_findings"`
	MissingProxyProto          int `json:"missing_proxy_proto"`
	TrustedProxyConcerns       int `json:"trusted_proxy_concerns"`
	ProxyProtocolMismatch      int `json:"proxy_protocol_mismatch"`
	UnprotectedUpstreamHeaders int `json:"unprotected_upstream_headers"`
	ExposedRealIP              int `json:"exposed_real_ip"`
}

var proxyImages = []string{
	"nginx", "haproxy", "traefik", "envoyproxy/envoy", "caddy",
	"kong", "apache", "httpd", "openresty",
}

var backendImages = []string{
	"node", "python", "ruby", "php", "golang", "openjdk", "mcr.microsoft.com",
	"django", "flask", "express", "rails", "spring", "fastapi", "gunicorn",
	"uvicorn", "tomcat", "jetty",
}

func isProxyImage(image string) bool {
	lower := strings.ToLower(image)
	for _, p := range proxyImages {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isBackendImage(image string) bool {
	lower := strings.ToLower(image)
	for _, b := range backendImages {
		if strings.Contains(lower, b) {
			return true
		}
	}
	return false
}

func hasProxyProtoEnv(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "proxy_protocol") ||
			strings.Contains(lower, "proxy_proto") ||
			strings.Contains(lower, "send-proxy") ||
			strings.Contains(lower, "proxyprotocol") {
			return true
		}
	}
	return false
}

func hasRealIPHeader(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "x-real-ip") ||
			strings.Contains(lower, "x-forwarded-for") ||
			strings.Contains(lower, "forwarded") ||
			strings.Contains(lower, "real_ip") {
			return true
		}
	}
	return false
}

func hasTrustedProxyConfig(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "trusted_proxy") ||
			strings.Contains(lower, "trusted_proxies") ||
			strings.Contains(lower, "set_real_ip_from") ||
			strings.Contains(lower, "forwarded_allow_ips") ||
			strings.Contains(lower, "trust_proxy") {
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

func analyzeService(svc compose.Service, file string, hasProxy bool) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	isProxy := isProxyImage(svc.Image)
	isBackend := isBackendImage(svc.Image)

	if isProxy && hasPublicPorts(svc) && !hasProxyProtoEnv(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "missing_proxy_proto",
			Message: fmt.Sprintf("Proxy service '%s' is publicly exposed but has no PROXY protocol configuration; client IP addresses may be lost for downstream services", svc.Name),
		})
	}

	if isBackend && hasProxy && !hasTrustedProxyConfig(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "trusted_proxy_concerns",
			Message: fmt.Sprintf("Backend service '%s' sits behind a proxy but has no trusted proxy configuration; it may accept spoofed X-Forwarded-For headers from untrusted sources", svc.Name),
		})
	}

	if isProxy && hasProxyProtoEnv(svc) {
		for _, e := range svc.Environment {
			lower := strings.ToLower(e)
			if (strings.Contains(lower, "proxy_protocol=v1") && strings.Contains(lower, "v2")) ||
				(strings.Contains(lower, "proxy_protocol=v2") && strings.Contains(lower, "v1")) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "proxy_protocol_mismatch",
					Message: fmt.Sprintf("Service '%s' has conflicting PROXY protocol version settings; version mismatch between proxy and backend causes connection failures", svc.Name),
				})
				break
			}
		}
	}

	if isBackend && hasPublicPorts(svc) && hasRealIPHeader(svc) && !hasProxy {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "unprotected_upstream_headers",
			Message: fmt.Sprintf("Backend service '%s' is directly exposed and processes forwarding headers (X-Forwarded-For / X-Real-IP); without a trusted proxy, attackers can spoof client IP addresses", svc.Name),
		})
	}

	if isBackend && hasRealIPHeader(svc) && !hasTrustedProxyConfig(svc) && hasProxy {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "exposed_real_ip",
			Message: fmt.Sprintf("Service '%s' uses forwarding headers but has no trusted-proxy allowlist; real client IP determination relies on unvalidated headers", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		hasProxy := false
		for _, svc := range cf.Services {
			if isProxyImage(svc.Image) {
				hasProxy = true
				break
			}
		}
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, hasProxy)
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
			case "missing_proxy_proto":
				s.MissingProxyProto++
			case "trusted_proxy_concerns":
				s.TrustedProxyConcerns++
			case "proxy_protocol_mismatch":
				s.ProxyProtocolMismatch++
			case "unprotected_upstream_headers":
				s.UnprotectedUpstreamHeaders++
			case "exposed_real_ip":
				s.ExposedRealIP++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Proxy Protocol Security Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Missing proxy protocol:        %d\n", r.Summary.MissingProxyProto)
	fmt.Fprintf(&b, "  Trusted proxy concerns:        %d\n", r.Summary.TrustedProxyConcerns)
	fmt.Fprintf(&b, "  Protocol version mismatch:     %d\n", r.Summary.ProxyProtocolMismatch)
	fmt.Fprintf(&b, "  Unprotected upstream headers:  %d\n", r.Summary.UnprotectedUpstreamHeaders)
	fmt.Fprintf(&b, "  Exposed real IP:               %d\n\n", r.Summary.ExposedRealIP)
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
