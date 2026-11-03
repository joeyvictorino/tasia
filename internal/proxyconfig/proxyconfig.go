package proxyconfig

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
	OpenProxy        int `json:"open_proxy"`
	InsecureUpstream int `json:"insecure_upstream"`
	ProxyAuthLeak    int `json:"proxy_auth_leak"`
	SSRFVector       int `json:"ssrf_vector"`
	HeaderInjection  int `json:"header_injection"`
	MissingTLS       int `json:"missing_tls"`
}

var openProxyIndicators = []string{
	"proxy_pass http://0.0.0.0",
	"proxy_pass http://*",
	"proxy_pass http://[::]",
	"listen 0.0.0.0:8080",
}

var insecureUpstreamPatterns = []string{
	"proxy_pass http://",
	"upstream_url=http://",
	"backend_url=http://",
	"target_url=http://",
}

var proxyAuthLeakPatterns = []string{
	"proxy_set_header authorization",
	"proxy_pass_header authorization",
	"proxy_set_header x-api-key",
	"proxy_set_header cookie",
}

var ssrfPatterns = []string{
	"proxy_pass $",
	"proxy_pass ${",
	"resolver",
}

var headerInjectionPatterns = []string{
	"proxy_set_header host $",
	"proxy_set_header x-forwarded-for $",
	"add_header $",
}

var missingTLSPatterns = []string{
	"ssl off", "ssl_verify off", "ssl_verify none",
	"insecure", "tls_skip_verify", "no_ssl",
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

	checkFields(&sr, svc)

	return sr
}

func checkFields(sr *ServiceResult, svc compose.Service) {
	sources := gatherText(svc)
	joined := strings.Join(sources, " ")
	lower := strings.ToLower(joined)

	if containsAny(lower, openProxyIndicators) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "proxy_open",
			Message: fmt.Sprintf("Service '%s' configures an open proxy binding to all interfaces; allows unauthorized traffic relay", svc.Name),
		})
	}

	if containsAny(lower, insecureUpstreamPatterns) && !strings.Contains(lower, "https://") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "proxy_insecure_upstream",
			Message: fmt.Sprintf("Service '%s' uses plaintext HTTP for upstream/backend connections; traffic is interceptable", svc.Name),
		})
	}

	if containsAny(lower, proxyAuthLeakPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "proxy_auth_leak",
			Message: fmt.Sprintf("Service '%s' forwards sensitive authentication headers through proxy; credential exposure risk", svc.Name),
		})
	}

	if containsAny(lower, ssrfPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "proxy_ssrf",
			Message: fmt.Sprintf("Service '%s' uses dynamic proxy target from variables; server-side request forgery vector", svc.Name),
		})
	}

	if containsAny(lower, headerInjectionPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "proxy_header_injection",
			Message: fmt.Sprintf("Service '%s' sets proxy headers from user-controlled variables; header injection possible", svc.Name),
		})
	}

	if containsAny(lower, missingTLSPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "proxy_missing_tls",
			Message: fmt.Sprintf("Service '%s' disables or skips TLS verification for proxy connections; man-in-the-middle risk", svc.Name),
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

func containsAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "proxy_open":
				s.OpenProxy++
			case "proxy_insecure_upstream":
				s.InsecureUpstream++
			case "proxy_auth_leak":
				s.ProxyAuthLeak++
			case "proxy_ssrf":
				s.SSRFVector++
			case "proxy_header_injection":
				s.HeaderInjection++
			case "proxy_missing_tls":
				s.MissingTLS++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Proxy Configuration Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Open proxy:             %d\n", r.Summary.OpenProxy)
	fmt.Fprintf(&b, "  Insecure upstream:      %d\n", r.Summary.InsecureUpstream)
	fmt.Fprintf(&b, "  Auth header leak:       %d\n", r.Summary.ProxyAuthLeak)
	fmt.Fprintf(&b, "  SSRF vectors:           %d\n", r.Summary.SSRFVector)
	fmt.Fprintf(&b, "  Header injection:       %d\n", r.Summary.HeaderInjection)
	fmt.Fprintf(&b, "  Missing TLS:            %d\n\n", r.Summary.MissingTLS)
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
