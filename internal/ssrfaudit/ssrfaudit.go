package ssrfaudit

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
	TotalServices        int `json:"total_services"`
	TotalFindings        int `json:"total_findings"`
	InternalURLExposed   int `json:"internal_url_exposed"`
	MetadataEndpoint     int `json:"metadata_endpoint"`
	UnrestrictedProxy    int `json:"unrestricted_proxy"`
	SSRFSinkNoValidation int `json:"ssrf_sink_no_validation"`
	PrivateNetworkAccess int `json:"private_network_access"`
}

var metadataEndpoints = []string{
	"169.254.169.254",
	"metadata.google.internal",
	"metadata.google",
	"100.100.100.200",
	"fd00:ec2::254",
}

var ssrfProxyImages = []string{
	"squid", "nginx", "haproxy", "traefik", "envoy",
	"tinyproxy", "privoxy", "polipo", "dante",
}

var ssrfSinkEnvKeys = []string{
	"webhook_url", "callback_url", "redirect_uri",
	"proxy_url", "upstream_url", "backend_url",
	"remote_url", "fetch_url", "download_url",
	"api_url", "endpoint_url", "service_url",
	"target_url", "destination_url",
}

var internalPrefixes = []string{
	"http://localhost", "http://127.0.0.1", "http://0.0.0.0",
	"http://[::1]", "http://10.", "http://172.16.", "http://172.17.",
	"http://172.18.", "http://172.19.", "http://172.2", "http://172.3",
	"http://192.168.",
}

func containsMetadataRef(env []string) bool {
	for _, e := range env {
		lower := strings.ToLower(e)
		for _, m := range metadataEndpoints {
			if strings.Contains(lower, m) {
				return true
			}
		}
	}
	return false
}

func isProxyImage(image string) bool {
	lower := strings.ToLower(image)
	for _, p := range ssrfProxyImages {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func hasSSRFSinkEnv(env []string) []string {
	var sinks []string
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		for _, s := range ssrfSinkEnvKeys {
			if strings.Contains(key, s) {
				sinks = append(sinks, parts[0])
				break
			}
		}
	}
	return sinks
}

func hasInternalURL(env []string) []string {
	var found []string
	for _, e := range env {
		lower := strings.ToLower(e)
		for _, prefix := range internalPrefixes {
			if strings.Contains(lower, prefix) {
				parts := strings.SplitN(e, "=", 2)
				if len(parts) >= 1 {
					found = append(found, parts[0])
				}
				break
			}
		}
	}
	return found
}

func hasPrivateNetworkAccess(svc compose.Service) bool {
	return svc.NetworkMode == "host" || svc.Privileged
}

func hasProxyPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		switch p.TargetPort {
		case 3128, 8080, 8443, 80, 443:
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if urls := hasInternalURL(svc.Environment); len(urls) > 0 {
		for _, u := range urls {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "internal_url_exposed",
				Message: fmt.Sprintf("Service '%s' has environment variable '%s' referencing an internal/private URL; if user-controllable, this could enable SSRF to internal services", svc.Name, u),
			})
		}
	}

	if containsMetadataRef(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "metadata_endpoint",
			Message: fmt.Sprintf("Service '%s' references a cloud metadata endpoint (169.254.169.254 or similar); ensure this is intentional and not reachable via user input", svc.Name),
		})
	}

	if isProxyImage(svc.Image) && hasProxyPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "unrestricted_proxy",
			Message: fmt.Sprintf("Service '%s' runs a proxy (%s) with exposed ports; an open proxy can be exploited for SSRF to reach internal services and cloud metadata", svc.Name, svc.Image),
		})
	}

	if sinks := hasSSRFSinkEnv(svc.Environment); len(sinks) > 0 {
		for _, s := range sinks {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "ssrf_sink_no_validation",
				Message: fmt.Sprintf("Service '%s' has URL-accepting env var '%s'; if populated from user input without validation, this is an SSRF vector", svc.Name, s),
			})
		}
	}

	if hasPrivateNetworkAccess(svc) && isProxyImage(svc.Image) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "private_network_access",
			Message: fmt.Sprintf("Service '%s' runs a proxy with host network or privileged mode; it can reach any internal service and cloud metadata without Docker network isolation", svc.Name),
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
			case "internal_url_exposed":
				s.InternalURLExposed++
			case "metadata_endpoint":
				s.MetadataEndpoint++
			case "unrestricted_proxy":
				s.UnrestrictedProxy++
			case "ssrf_sink_no_validation":
				s.SSRFSinkNoValidation++
			case "private_network_access":
				s.PrivateNetworkAccess++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SSRF Vulnerability Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Internal URL exposed:          %d\n", r.Summary.InternalURLExposed)
	fmt.Fprintf(&b, "  Metadata endpoint refs:        %d\n", r.Summary.MetadataEndpoint)
	fmt.Fprintf(&b, "  Unrestricted proxies:          %d\n", r.Summary.UnrestrictedProxy)
	fmt.Fprintf(&b, "  SSRF sink (no validation):     %d\n", r.Summary.SSRFSinkNoValidation)
	fmt.Fprintf(&b, "  Private network access:        %d\n\n", r.Summary.PrivateNetworkAccess)
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
