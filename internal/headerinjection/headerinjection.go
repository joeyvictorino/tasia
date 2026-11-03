package headerinjection

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
	TotalServices           int `json:"total_services"`
	TotalFindings           int `json:"total_findings"`
	UserInputInHeaders      int `json:"user_input_in_headers"`
	MissingSecurityHeaders  int `json:"missing_security_headers"`
	InsecureCORSHeaders     int `json:"insecure_cors_headers"`
	HostHeaderForwarding    int `json:"host_header_forwarding"`
	ResponseSplittingRisk   int `json:"response_splitting_risk"`
}

var proxyImages = []string{
	"nginx", "haproxy", "traefik", "envoy", "caddy",
	"apache", "httpd", "kong", "apisix",
}

var headerForwardingEnvKeys = []string{
	"proxy_set_header", "add_header", "header_upstream",
	"request_header", "response_header", "x-forwarded",
	"x_forwarded", "forward_headers", "trusted_proxies",
}

var userInputHeaderEnvKeys = []string{
	"x-custom-", "x_custom_", "header_from_",
	"user_agent", "referer_header", "origin_header",
	"custom_header", "client_header",
}

var dangerousCORSValues = []string{
	"access-control-allow-origin: *",
	"access_control_allow_origin=*",
	"cors_origin=*",
	"allowed_origins=*",
	"cors_allow_all",
	"cors_enabled=true",
}

var securityHeaders = []string{
	"x-content-type-options",
	"x-frame-options",
	"strict-transport-security",
	"content-security-policy",
	"x-xss-protection",
}

var hostHeaderEnvKeys = []string{
	"proxy_pass_host", "preserve_host", "forward_host",
	"host_header", "x-forwarded-host", "x_forwarded_host",
}

var responseSplittingPatterns = []string{
	"\\r\\n", "%0d%0a", "\\n\\n", "%0a%0a",
	"crlf", "newline_in_header",
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

func envContainsAny(env []string, patterns []string) bool {
	for _, e := range env {
		lower := strings.ToLower(e)
		for _, p := range patterns {
			if strings.Contains(lower, p) {
				return true
			}
		}
	}
	return false
}

func countEnvMatches(env []string, patterns []string) int {
	count := 0
	for _, e := range env {
		lower := strings.ToLower(e)
		for _, p := range patterns {
			if strings.Contains(lower, p) {
				count++
				break
			}
		}
	}
	return count
}

func hasSecurityHeaderConfig(env []string, labels map[string]string) bool {
	for _, e := range env {
		lower := strings.ToLower(e)
		for _, h := range securityHeaders {
			if strings.Contains(lower, h) {
				return true
			}
		}
	}
	for k := range labels {
		lower := strings.ToLower(k)
		for _, h := range securityHeaders {
			if strings.Contains(lower, h) {
				return true
			}
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if envContainsAny(svc.Environment, userInputHeaderEnvKeys) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "user_input_in_headers",
			Message: fmt.Sprintf("Service '%s' has environment variables suggesting user-controlled HTTP headers; if header values are not sanitized, this enables header injection attacks", svc.Name),
		})
	}

	if isProxyImage(svc.Image) && !hasSecurityHeaderConfig(svc.Environment, svc.Labels) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "missing_security_headers",
			Message: fmt.Sprintf("Service '%s' runs a web server/proxy (%s) without security headers configured (X-Content-Type-Options, X-Frame-Options, CSP, HSTS); responses may be vulnerable to clickjacking, MIME sniffing, and XSS", svc.Name, svc.Image),
		})
	}

	if envContainsAny(svc.Environment, dangerousCORSValues) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "insecure_cors_headers",
			Message: fmt.Sprintf("Service '%s' has wildcard CORS origin (*); any website can make cross-origin requests to this service, potentially exfiltrating data or triggering actions", svc.Name),
		})
	}

	if isProxyImage(svc.Image) && envContainsAny(svc.Environment, hostHeaderEnvKeys) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "host_header_forwarding",
			Message: fmt.Sprintf("Service '%s' forwards the Host header from client requests; if not validated, this can lead to host header injection enabling cache poisoning, password reset hijacking, and SSRF", svc.Name),
		})
	}

	if envContainsAny(svc.Environment, responseSplittingPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "response_splitting_risk",
			Message: fmt.Sprintf("Service '%s' has environment variables containing CRLF or newline patterns; this may indicate HTTP response splitting vulnerability if injected into response headers", svc.Name),
		})
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
			case "user_input_in_headers":
				s.UserInputInHeaders++
			case "missing_security_headers":
				s.MissingSecurityHeaders++
			case "insecure_cors_headers":
				s.InsecureCORSHeaders++
			case "host_header_forwarding":
				s.HostHeaderForwarding++
			case "response_splitting_risk":
				s.ResponseSplittingRisk++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP Header Injection Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  User input in headers:         %d\n", r.Summary.UserInputInHeaders)
	fmt.Fprintf(&b, "  Missing security headers:      %d\n", r.Summary.MissingSecurityHeaders)
	fmt.Fprintf(&b, "  Insecure CORS headers:         %d\n", r.Summary.InsecureCORSHeaders)
	fmt.Fprintf(&b, "  Host header forwarding:        %d\n", r.Summary.HostHeaderForwarding)
	fmt.Fprintf(&b, "  Response splitting risk:       %d\n\n", r.Summary.ResponseSplittingRisk)
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
