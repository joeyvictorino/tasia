package oauth2audit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path:     "docker-compose.yml",
			Services: services,
		}},
	}
}

func svc(name, image string) compose.Service {
	return compose.Service{Name: name, Image: image}
}

func publicPort(host, target int) compose.PortMapping {
	return compose.PortMapping{HostPort: host, TargetPort: target}
}

func localhostPort(host, target int) compose.PortMapping {
	return compose.PortMapping{HostPort: host, TargetPort: target, HostIP: "127.0.0.1"}
}

func findByRule(services []ServiceResult, rule string) []Finding {
	var found []Finding
	for _, sr := range services {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				found = append(found, f)
			}
		}
	}
	return found
}

func TestWeakClientSecret(t *testing.T) {
	s := compose.Service{
		Name:        "idp",
		Image:       "keycloak:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"CLIENT_SECRET=changeme"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_client_secret")
	if len(findings) == 0 {
		t.Fatal("expected weak_client_secret finding for weak secret")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestShortClientSecret(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "hydra:latest",
		Ports:       []compose.PortMapping{publicPort(4444, 4444)},
		Environment: []string{"OAUTH_SECRET=abc123"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_client_secret")
	if len(findings) == 0 {
		t.Fatal("expected weak_client_secret for short secret")
	}
}

func TestStrongClientSecret(t *testing.T) {
	s := compose.Service{
		Name:        "idp",
		Image:       "keycloak:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"CLIENT_SECRET=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "weak_client_secret")
	if len(findings) != 0 {
		t.Fatal("should not flag strong client secret")
	}
}

func TestImplicitGrant(t *testing.T) {
	s := compose.Service{
		Name:        "idp",
		Image:       "keycloak:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"GRANT_TYPE=implicit"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "implicit_grant")
	if len(findings) == 0 {
		t.Fatal("expected implicit_grant finding")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestResponseTypeToken(t *testing.T) {
	s := compose.Service{
		Name:        "auth",
		Image:       "dex:latest",
		Ports:       []compose.PortMapping{publicPort(5556, 5556)},
		Environment: []string{"RESPONSE_TYPE=token"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "implicit_grant")
	if len(findings) == 0 {
		t.Fatal("expected implicit_grant for response_type=token")
	}
}

func TestNoImplicitGrant(t *testing.T) {
	s := compose.Service{
		Name:        "idp",
		Image:       "keycloak:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"GRANT_TYPE=authorization_code"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "implicit_grant")
	if len(findings) != 0 {
		t.Fatal("should not flag authorization_code grant")
	}
}

func TestHTTPRedirectURI(t *testing.T) {
	s := compose.Service{
		Name:        "idp",
		Image:       "keycloak:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"REDIRECT_URI=http://example.com/callback"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_https_redirect")
	if len(findings) == 0 {
		t.Fatal("expected no_https_redirect for HTTP redirect URI")
	}
}

func TestHTTPSRedirectURI(t *testing.T) {
	s := compose.Service{
		Name:        "idp",
		Image:       "keycloak:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"REDIRECT_URI=https://example.com/callback"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_https_redirect")
	if len(findings) != 0 {
		t.Fatal("should not flag HTTPS redirect URI")
	}
}

func TestMissingPKCE(t *testing.T) {
	s := compose.Service{
		Name:        "idp",
		Image:       "keycloak:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"OAUTH_ENABLED=true"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_pkce")
	if len(findings) == 0 {
		t.Fatal("expected missing_pkce for OAuth service without PKCE")
	}
}

func TestPKCEConfigured(t *testing.T) {
	s := compose.Service{
		Name:        "idp",
		Image:       "keycloak:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"PKCE_ENABLED=true"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_pkce")
	if len(findings) != 0 {
		t.Fatal("should not flag missing_pkce when PKCE configured")
	}
}

func TestWildcardRedirect(t *testing.T) {
	s := compose.Service{
		Name:        "idp",
		Image:       "keycloak:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"REDIRECT_URIS=https://*.example.com/callback"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "open_redirect")
	if len(findings) == 0 {
		t.Fatal("expected open_redirect for wildcard redirect URI")
	}
}

func TestLocalhostRedirect(t *testing.T) {
	s := compose.Service{
		Name:        "idp",
		Image:       "keycloak:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"REDIRECT_URI=http://localhost:3000/callback"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "open_redirect")
	if len(findings) == 0 {
		t.Fatal("expected open_redirect for localhost redirect URI")
	}
}

func TestNonOAuthServiceNoFindings(t *testing.T) {
	s := svc("redis", "redis:7")
	r := Analyze(collected(s))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected no findings for non-OAuth service, got %d", r.Summary.TotalFindings)
	}
}

func TestOAuthDetectedByEnv(t *testing.T) {
	s := compose.Service{
		Name:        "app",
		Image:       "myapp:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"OIDC_ISSUER=https://auth.example.com"},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for service with OIDC env")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Analyze(collected(svc("keycloak", "keycloak:latest")))
	text := FormatText(r)
	if !strings.Contains(text, "OAuth2/OIDC Security Analysis") {
		t.Fatal("FormatText missing header")
	}
}

func TestSummaryCountsCorrect(t *testing.T) {
	s1 := compose.Service{
		Name:        "idp",
		Image:       "keycloak:latest",
		Ports:       []compose.PortMapping{publicPort(8080, 8080)},
		Environment: []string{"CLIENT_SECRET=test", "GRANT_TYPE=implicit"},
	}
	s2 := svc("redis", "redis:7")
	r := Analyze(collected(s1, s2))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WeakClientSecret != 1 {
		t.Fatalf("expected 1 weak_client_secret, got %d", r.Summary.WeakClientSecret)
	}
	if r.Summary.ImplicitGrant != 1 {
		t.Fatalf("expected 1 implicit_grant, got %d", r.Summary.ImplicitGrant)
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := &collect.Collected{
		Root: "/multi",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{svc("idp", "keycloak:latest")}},
			{Path: "docker-compose.dev.yml", Services: []compose.Service{svc("dev-auth", "dex:latest")}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestAuthentikDetected(t *testing.T) {
	s := compose.Service{
		Name:        "sso",
		Image:       "ghcr.io/goauthentik/server:latest",
		Ports:       []compose.PortMapping{publicPort(9000, 9000)},
		Environment: []string{"AUTHENTIK_SECRET_KEY=test"},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for authentik service")
	}
}

func TestOAuth2ProxyDetected(t *testing.T) {
	s := compose.Service{
		Name:        "proxy",
		Image:       "oauth2-proxy/oauth2-proxy:latest",
		Ports:       []compose.PortMapping{publicPort(4180, 4180)},
		Environment: []string{"OAUTH2_PROXY_CLIENT_ID=myapp"},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings > 0 || !isOAuthService(s) {
		if !isOAuthService(s) {
			t.Fatal("expected oauth2-proxy to be detected as OAuth service")
		}
	}
}

func TestHTTPRedirectNotFlaggedOnLocalhost(t *testing.T) {
	s := compose.Service{
		Name:        "idp",
		Image:       "keycloak:latest",
		Ports:       []compose.PortMapping{localhostPort(8080, 8080)},
		Environment: []string{"REDIRECT_URI=http://example.com/callback"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "no_https_redirect")
	if len(findings) != 0 {
		t.Fatal("should not flag HTTP redirect on localhost binding")
	}
}
