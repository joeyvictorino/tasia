package apigateway

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
	TotalServices         int `json:"total_services"`
	TotalFindings         int `json:"total_findings"`
	NoGateway             int `json:"no_gateway"`
	GatewayNoAuth         int `json:"gateway_no_auth"`
	GatewayNoRateLimit    int `json:"gateway_no_rate_limit"`
	DirectExposure        int `json:"direct_exposure"`
	GatewayNoTLS          int `json:"gateway_no_tls"`
}

var gatewayImages = []string{
	"kong", "traefik", "nginx", "haproxy", "envoyproxy",
	"apisix", "tyk", "gravitee", "express-gateway",
	"api-gateway", "apigateway", "zuul", "spring-cloud-gateway",
}

var backendImages = []string{
	"node", "python", "flask", "django", "fastapi",
	"express", "rails", "spring", "tomcat", "jetty",
	"gunicorn", "uvicorn", "gin", "fiber", "echo",
}

var apiPorts = []int{3000, 5000, 8000, 8080, 8443, 9000, 4000}

func isGateway(svc compose.Service) bool {
	lower := strings.ToLower(svc.Image)
	for _, img := range gatewayImages {
		if strings.Contains(lower, img) {
			return true
		}
	}
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "api_gateway") ||
			strings.Contains(lower, "gateway_mode") ||
			strings.Contains(lower, "reverse_proxy") {
			return true
		}
	}
	return false
}

func isBackendService(svc compose.Service) bool {
	lower := strings.ToLower(svc.Image)
	for _, img := range backendImages {
		if strings.Contains(lower, img) {
			return true
		}
	}
	for _, p := range svc.Ports {
		for _, ap := range apiPorts {
			if p.TargetPort == ap {
				return true
			}
		}
	}
	return false
}

func hasPublicPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if p.IsAllInterfaces() {
			return true
		}
	}
	return false
}

func hasGatewayAuth(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "auth_plugin") ||
			strings.Contains(lower, "key-auth") ||
			strings.Contains(lower, "jwt_secret") ||
			strings.Contains(lower, "api_key") ||
			strings.Contains(lower, "oauth") ||
			strings.Contains(lower, "basic_auth") ||
			strings.Contains(lower, "auth_enabled") ||
			strings.Contains(lower, "authentication") {
			return true
		}
	}
	return false
}

func hasRateLimit(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "rate_limit") ||
			strings.Contains(lower, "ratelimit") ||
			strings.Contains(lower, "throttle") ||
			strings.Contains(lower, "requests_per") ||
			strings.Contains(lower, "max_requests") {
			return true
		}
	}
	return false
}

func hasGatewayTLS(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "ssl") ||
			strings.Contains(lower, "tls") ||
			strings.Contains(lower, "https") ||
			strings.Contains(lower, "cert") {
			return true
		}
	}
	for _, p := range svc.Ports {
		if p.TargetPort == 443 || p.TargetPort == 8443 {
			return true
		}
	}
	return false
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}

	var gateways []compose.Service
	var backends []compose.Service

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if isGateway(svc) {
				gateways = append(gateways, svc)
			}
			if isBackendService(svc) {
				backends = append(backends, svc)
			}
		}
	}

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := ServiceResult{Service: svc.Name, File: cf.Path}

			if isGateway(svc) {
				if !hasGatewayAuth(svc) && hasPublicPort(svc) {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "high",
						Rule:    "gateway_no_auth",
						Message: fmt.Sprintf("API gateway '%s' is publicly exposed without authentication plugins; unauthenticated APIs allow unauthorized access", svc.Name),
					})
				}

				if !hasRateLimit(svc) && hasPublicPort(svc) {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "medium",
						Rule:    "gateway_no_rate_limit",
						Message: fmt.Sprintf("API gateway '%s' has no rate limiting configured; services are vulnerable to abuse and denial of service", svc.Name),
					})
				}

				if !hasGatewayTLS(svc) && hasPublicPort(svc) {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "high",
						Rule:    "gateway_no_tls",
						Message: fmt.Sprintf("API gateway '%s' is publicly exposed without TLS; API traffic can be intercepted", svc.Name),
					})
				}
			}

			if isBackendService(svc) && !isGateway(svc) && hasPublicPort(svc) && len(gateways) > 0 {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "direct_exposure",
					Message: fmt.Sprintf("Backend service '%s' is directly exposed despite API gateway presence; route all traffic through the gateway to enforce security policies", svc.Name),
				})
			}

			if isBackendService(svc) && hasPublicPort(svc) && len(gateways) == 0 {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "no_gateway",
					Message: fmt.Sprintf("Backend service '%s' is publicly exposed with no API gateway present; add a gateway to centralize authentication, rate limiting, and TLS termination", svc.Name),
				})
			}

			r.Services = append(r.Services, sr)
			_ = backends
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
			case "no_gateway":
				s.NoGateway++
			case "gateway_no_auth":
				s.GatewayNoAuth++
			case "gateway_no_rate_limit":
				s.GatewayNoRateLimit++
			case "direct_exposure":
				s.DirectExposure++
			case "gateway_no_tls":
				s.GatewayNoTLS++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "API Gateway Security Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No gateway present:          %d\n", r.Summary.NoGateway)
	fmt.Fprintf(&b, "  Gateway missing auth:        %d\n", r.Summary.GatewayNoAuth)
	fmt.Fprintf(&b, "  Gateway missing rate limit:   %d\n", r.Summary.GatewayNoRateLimit)
	fmt.Fprintf(&b, "  Direct backend exposure:     %d\n", r.Summary.DirectExposure)
	fmt.Fprintf(&b, "  Gateway missing TLS:         %d\n\n", r.Summary.GatewayNoTLS)
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
