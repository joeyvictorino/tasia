package ratelimit

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
	Exposed  bool      `json:"exposed"`
	HasLimit bool      `json:"has_rate_limit"`
	Findings []Finding `json:"findings"`
}

type Summary struct {
	TotalServices  int `json:"total_services"`
	ExposedServices int `json:"exposed_services"`
	WithRateLimit   int `json:"with_rate_limit"`
	WithoutRateLimit int `json:"without_rate_limit"`
	TotalFindings  int `json:"total_findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var apiImagePrefixes = []string{
	"nginx", "traefik", "caddy", "envoy", "haproxy", "kong",
	"express", "fastapi", "flask", "django", "rails", "spring",
	"node", "python", "go", "java", "dotnet",
}

var rateLimitIndicators = []string{
	"rate_limit", "ratelimit", "rate-limit",
	"throttle", "throttling",
	"burst", "burst_size",
	"limit_req", "limit_conn",
	"max_rate", "requests_per",
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}

	for _, sr := range r.Services {
		r.Summary.TotalServices++
		if sr.Exposed {
			r.Summary.ExposedServices++
			if sr.HasLimit {
				r.Summary.WithRateLimit++
			} else {
				r.Summary.WithoutRateLimit++
			}
		}
		r.Summary.TotalFindings += len(sr.Findings)
	}
	return r
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Service: svc.Name,
		File:    file,
	}

	sr.Exposed = len(svc.Ports) > 0
	if !sr.Exposed {
		return sr
	}

	hasLimit := checkRateLimitConfig(svc)
	sr.HasLimit = hasLimit

	isAPI := isAPIService(svc)

	if !hasLimit && isAPI {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "warning",
			Rule:    "rate_limit_missing_api",
			Message: fmt.Sprintf("Service %q exposes ports and appears to be an API service but has no rate limiting configuration", svc.Name),
		})
	} else if !hasLimit && sr.Exposed {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "rate_limit_missing_exposed",
			Message: fmt.Sprintf("Service %q exposes ports without rate limiting", svc.Name),
		})
	}

	for _, p := range svc.Ports {
		port := fmt.Sprintf("%d", p.TargetPort)
		if isHighValuePort(port) && !hasLimit {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "warning",
				Rule:    "rate_limit_missing_sensitive_port",
				Message: fmt.Sprintf("Service %q exposes sensitive port %s without rate limiting", svc.Name, port),
			})
		}
	}

	return sr
}

func checkRateLimitConfig(svc compose.Service) bool {
	allText := strings.ToLower(strings.Join(svc.Environment, " "))

	for _, label := range svc.Labels {
		allText += " " + strings.ToLower(label)
	}

	if len(svc.Command) > 0 {
		allText += " " + strings.ToLower(strings.Join(svc.Command, " "))
	}

	for _, ind := range rateLimitIndicators {
		if strings.Contains(allText, ind) {
			return true
		}
	}
	return false
}

func isAPIService(svc compose.Service) bool {
	img := strings.ToLower(svc.Image)
	for _, prefix := range apiImagePrefixes {
		if strings.Contains(img, prefix) {
			return true
		}
	}
	name := strings.ToLower(svc.Name)
	apiNames := []string{"api", "gateway", "proxy", "web", "frontend", "backend", "server"}
	for _, n := range apiNames {
		if strings.Contains(name, n) {
			return true
		}
	}
	return false
}

func isHighValuePort(port string) bool {
	sensitive := map[string]bool{
		"80": true, "443": true, "8080": true, "8443": true,
		"3000": true, "5000": true, "8000": true, "9000": true,
	}
	return sensitive[port]
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Rate Limit Analysis: %s\n", r.Path)
	fmt.Fprintf(&b, "%s\n\n", strings.Repeat("=", 40))
	fmt.Fprintf(&b, "Services: %d total, %d exposed, %d with rate limit, %d without\n\n",
		r.Summary.TotalServices, r.Summary.ExposedServices,
		r.Summary.WithRateLimit, r.Summary.WithoutRateLimit)

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "Service: %s (%s)\n", sr.Service, sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "  [%s] %s: %s\n", f.Level, f.Rule, f.Message)
		}
		fmt.Fprintln(&b)
	}

	return b.String()
}
