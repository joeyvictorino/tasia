package corsconfig

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
	WildcardOrigin      int `json:"wildcard_origin"`
	CredentialsWildcard int `json:"credentials_wildcard"`
	UnsafeHeaders       int `json:"unsafe_headers"`
	UnsafeMethods       int `json:"unsafe_methods"`
	NullOrigin          int `json:"null_origin"`
	MissingCORS         int `json:"missing_cors"`
}

var wildcardOriginPatterns = []string{
	"access-control-allow-origin: *",
	"access-control-allow-origin *",
	"cors_origin=*", "cors_allowed_origins=*",
	"allow_origins: [\"*\"]", "allow_origins=*",
	"allowed_origins *", "origin *",
}

var credWildcardPatterns = []string{
	"access-control-allow-credentials: true",
	"allow_credentials=true", "cors_credentials=true",
	"credentials: true", "withcredentials=true",
}

var unsafeHeaderPatterns = []string{
	"access-control-allow-headers: *",
	"allow_headers=*", "cors_headers=*",
	"expose-headers: *", "cors_expose_all",
}

var unsafeMethodPatterns = []string{
	"access-control-allow-methods: *",
	"allow_methods=*", "cors_methods=*",
	"access-control-allow-methods: delete",
	"access-control-allow-methods: patch",
}

var nullOriginPatterns = []string{
	"access-control-allow-origin: null",
	"cors_origin=null", "allow_origins: null",
	"allowed_origins null", "origin null",
}

var corsNeededIndicators = []string{
	"api", "graphql", "rest", "endpoint",
	"backend", "proxy_pass", "upstream",
}

var corsConfiguredIndicators = []string{
	"cors", "access-control", "allow-origin",
	"allow_origins", "cors_", "cross-origin",
}

func gatherText(svc compose.Service) string {
	var parts []string
	parts = append(parts, svc.Entrypoint...)
	parts = append(parts, svc.Command...)
	parts = append(parts, svc.Environment...)
	for _, v := range svc.Labels {
		parts = append(parts, v)
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func containsAny(text string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(text, p) {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}
	text := gatherText(svc)

	hasWildcard := containsAny(text, wildcardOriginPatterns)
	hasCreds := containsAny(text, credWildcardPatterns)

	if hasWildcard {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "cors_wildcard_origin",
			Message: fmt.Sprintf("Service %q allows any origin via wildcard CORS", svc.Name),
		})
	}

	if hasCreds && hasWildcard {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "cors_credentials_wildcard",
			Message: fmt.Sprintf("Service %q allows credentials with wildcard origin", svc.Name),
		})
	}

	if containsAny(text, unsafeHeaderPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cors_unsafe_headers",
			Message: fmt.Sprintf("Service %q exposes all headers via wildcard CORS header policy", svc.Name),
		})
	}

	if containsAny(text, unsafeMethodPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cors_unsafe_methods",
			Message: fmt.Sprintf("Service %q allows dangerous HTTP methods via CORS", svc.Name),
		})
	}

	if containsAny(text, nullOriginPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "cors_null_origin",
			Message: fmt.Sprintf("Service %q allows null origin which can be spoofed", svc.Name),
		})
	}

	needsCORS := containsAny(text, corsNeededIndicators)
	hasCORS := containsAny(text, corsConfiguredIndicators)
	if needsCORS && !hasCORS {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "cors_missing",
			Message: fmt.Sprintf("Service %q appears to be an API but has no CORS configuration", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Summary.TotalServices++
			for _, f := range sr.Findings {
				r.Summary.TotalFindings++
				switch f.Rule {
				case "cors_wildcard_origin":
					r.Summary.WildcardOrigin++
				case "cors_credentials_wildcard":
					r.Summary.CredentialsWildcard++
				case "cors_unsafe_headers":
					r.Summary.UnsafeHeaders++
				case "cors_unsafe_methods":
					r.Summary.UnsafeMethods++
				case "cors_null_origin":
					r.Summary.NullOrigin++
				case "cors_missing":
					r.Summary.MissingCORS++
				}
			}
			r.Services = append(r.Services, sr)
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CORS Configuration Audit (%s)\n", r.Path)
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Services scanned:   %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Total findings:     %d\n\n", r.Summary.TotalFindings)

	if r.Summary.TotalFindings == 0 {
		b.WriteString("  All services: no findings.\n")
		return b.String()
	}

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s (%s)\n", sr.Service, sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Level, f.Rule, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
