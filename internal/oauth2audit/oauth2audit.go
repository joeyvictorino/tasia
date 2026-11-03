package oauth2audit

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
	WeakClientSecret      int `json:"weak_client_secret"`
	ImplicitGrant         int `json:"implicit_grant"`
	NoHTTPS               int `json:"no_https"`
	MissingPKCE           int `json:"missing_pkce"`
	OpenRedirect          int `json:"open_redirect"`
}

var oauthImages = []string{
	"keycloak", "dex", "hydra", "authelia", "authentik",
	"casdoor", "zitadel", "fusionauth", "gluu", "wso2",
	"auth0", "okta", "oauth2-proxy", "oauth2proxy",
}

func isOAuthService(svc compose.Service) bool {
	lower := strings.ToLower(svc.Image)
	for _, img := range oauthImages {
		if strings.Contains(lower, img) {
			return true
		}
	}
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "oauth") ||
			strings.Contains(lower, "oidc") ||
			strings.Contains(lower, "client_id") ||
			strings.Contains(lower, "client_secret") {
			return true
		}
	}
	return false
}

func hasWeakClientSecret(svc compose.Service) bool {
	weakSecrets := []string{
		"secret", "password", "changeme", "test", "demo",
		"example", "default", "admin", "12345",
	}
	for _, e := range svc.Environment {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		val := strings.ToLower(parts[1])
		if (strings.Contains(key, "client_secret") || strings.Contains(key, "oauth_secret")) && val != "" {
			for _, w := range weakSecrets {
				if val == w {
					return true
				}
			}
			if len(val) < 16 {
				return true
			}
		}
	}
	return false
}

func usesImplicitGrant(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "response_type=token") ||
			strings.Contains(lower, "implicit_grant=true") ||
			strings.Contains(lower, "grant_type=implicit") ||
			strings.Contains(lower, "implicit=enabled") ||
			strings.Contains(lower, "allow_implicit=true") {
			return true
		}
	}
	return false
}

func usesHTTPS(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "https://") ||
			strings.Contains(lower, "ssl=true") ||
			strings.Contains(lower, "tls=true") ||
			strings.Contains(lower, "force_ssl") ||
			strings.Contains(lower, "require_https") {
			return true
		}
	}
	return false
}

func hasHTTPRedirectURI(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		key := strings.SplitN(lower, "=", 2)[0]
		if strings.Contains(key, "redirect") && strings.Contains(lower, "http://") {
			return true
		}
	}
	return false
}

func hasPKCE(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "pkce") ||
			strings.Contains(lower, "code_challenge") ||
			strings.Contains(lower, "s256") {
			return true
		}
	}
	return false
}

func hasWildcardRedirect(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		key := strings.SplitN(lower, "=", 2)[0]
		if !strings.Contains(key, "redirect") {
			continue
		}
		if strings.Contains(lower, "*") ||
			strings.Contains(lower, "localhost") ||
			strings.Contains(lower, "0.0.0.0") {
			return true
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

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isOAuthService(svc) {
		return sr
	}

	if hasWeakClientSecret(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "weak_client_secret",
			Message: fmt.Sprintf("OAuth2 service '%s' has a weak or short client secret; use a cryptographically random secret of at least 32 characters", svc.Name),
		})
	}

	if usesImplicitGrant(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "implicit_grant",
			Message: fmt.Sprintf("OAuth2 service '%s' uses the implicit grant flow which exposes tokens in the URL; use authorization code flow with PKCE instead", svc.Name),
		})
	}

	if hasHTTPRedirectURI(svc) && hasPublicPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "no_https_redirect",
			Message: fmt.Sprintf("OAuth2 service '%s' has HTTP (non-HTTPS) redirect URIs on a public port; tokens can be intercepted in transit", svc.Name),
		})
	}

	if !hasPKCE(svc) && hasPublicPort(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "missing_pkce",
			Message: fmt.Sprintf("OAuth2 service '%s' does not appear to require PKCE; public clients should use PKCE to prevent authorization code interception", svc.Name),
		})
	}

	if hasWildcardRedirect(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "open_redirect",
			Message: fmt.Sprintf("OAuth2 service '%s' has wildcard or overly permissive redirect URIs; restrict redirects to exact registered URIs to prevent open redirect attacks", svc.Name),
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
			case "weak_client_secret":
				s.WeakClientSecret++
			case "implicit_grant":
				s.ImplicitGrant++
			case "no_https_redirect":
				s.NoHTTPS++
			case "missing_pkce":
				s.MissingPKCE++
			case "open_redirect":
				s.OpenRedirect++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "OAuth2/OIDC Security Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Weak client secrets:         %d\n", r.Summary.WeakClientSecret)
	fmt.Fprintf(&b, "  Implicit grant flow:         %d\n", r.Summary.ImplicitGrant)
	fmt.Fprintf(&b, "  Non-HTTPS redirects:         %d\n", r.Summary.NoHTTPS)
	fmt.Fprintf(&b, "  Missing PKCE:                %d\n", r.Summary.MissingPKCE)
	fmt.Fprintf(&b, "  Open redirect risk:          %d\n\n", r.Summary.OpenRedirect)
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
