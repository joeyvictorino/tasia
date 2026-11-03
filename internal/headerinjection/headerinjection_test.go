package headerinjection

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

func TestUserInputInHeadersCustom(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "node:20",
		Environment: []string{"X-CUSTOM-AUTH=bearer-token"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "user_input_in_headers")
	if len(findings) == 0 {
		t.Fatal("expected user_input_in_headers for x-custom- env var")
	}
}

func TestUserInputInHeadersClientHeader(t *testing.T) {
	s := compose.Service{
		Name:        "gateway",
		Image:       "nginx:latest",
		Environment: []string{"CLIENT_HEADER_FORWARDING=true"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "user_input_in_headers")
	if len(findings) == 0 {
		t.Fatal("expected user_input_in_headers for client_header env var")
	}
}

func TestNoUserInputForNormalEnv(t *testing.T) {
	s := compose.Service{
		Name:        "app",
		Image:       "node:20",
		Environment: []string{"NODE_ENV=production", "PORT=3000"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "user_input_in_headers")
	if len(findings) != 0 {
		t.Fatal("normal env vars should not trigger user_input_in_headers")
	}
}

func TestMissingSecurityHeadersNginx(t *testing.T) {
	s := svc("web", "nginx:1.25")
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_security_headers")
	if len(findings) == 0 {
		t.Fatal("expected missing_security_headers for nginx without security header config")
	}
}

func TestMissingSecurityHeadersTraefik(t *testing.T) {
	s := svc("proxy", "traefik:v2.10")
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_security_headers")
	if len(findings) == 0 {
		t.Fatal("expected missing_security_headers for traefik without security header config")
	}
}

func TestNoMissingSecurityHeadersWithConfig(t *testing.T) {
	s := compose.Service{
		Name:        "web",
		Image:       "nginx:1.25",
		Environment: []string{"X-CONTENT-TYPE-OPTIONS=nosniff"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_security_headers")
	if len(findings) != 0 {
		t.Fatal("proxy with security header config should not trigger missing_security_headers")
	}
}

func TestNoMissingSecurityHeadersNonProxy(t *testing.T) {
	s := svc("db", "postgres:16")
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_security_headers")
	if len(findings) != 0 {
		t.Fatal("non-proxy image should not trigger missing_security_headers")
	}
}

func TestNoMissingSecurityHeadersWithLabel(t *testing.T) {
	s := compose.Service{
		Name:   "web",
		Image:  "nginx:1.25",
		Labels: map[string]string{"traefik.http.headers.content-security-policy": "default-src 'self'"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_security_headers")
	if len(findings) != 0 {
		t.Fatal("proxy with security header label should not trigger missing_security_headers")
	}
}

func TestInsecureCORSWildcard(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "node:20",
		Environment: []string{"ACCESS-CONTROL-ALLOW-ORIGIN: *"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_cors_headers")
	if len(findings) == 0 {
		t.Fatal("expected insecure_cors_headers for wildcard CORS origin")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestInsecureCORSEnvVar(t *testing.T) {
	s := compose.Service{
		Name:        "gateway",
		Image:       "envoy:latest",
		Environment: []string{"CORS_ALLOW_ALL=true"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_cors_headers")
	if len(findings) == 0 {
		t.Fatal("expected insecure_cors_headers for CORS_ALLOW_ALL env")
	}
}

func TestNoInsecureCORSForRestrictedOrigin(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "node:20",
		Environment: []string{"CORS_ORIGIN=https://example.com"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "insecure_cors_headers")
	if len(findings) != 0 {
		t.Fatal("restricted CORS origin should not trigger insecure_cors_headers")
	}
}

func TestHostHeaderForwardingNginx(t *testing.T) {
	s := compose.Service{
		Name:        "proxy",
		Image:       "nginx:1.25",
		Environment: []string{"PROXY_PASS_HOST=on"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "host_header_forwarding")
	if len(findings) == 0 {
		t.Fatal("expected host_header_forwarding for nginx with proxy_pass_host")
	}
}

func TestHostHeaderForwardingHAProxy(t *testing.T) {
	s := compose.Service{
		Name:        "lb",
		Image:       "haproxy:2.8",
		Environment: []string{"X-FORWARDED-HOST=client"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "host_header_forwarding")
	if len(findings) == 0 {
		t.Fatal("expected host_header_forwarding for haproxy with x-forwarded-host")
	}
}

func TestNoHostHeaderForwardingNonProxy(t *testing.T) {
	s := compose.Service{
		Name:        "app",
		Image:       "node:20",
		Environment: []string{"PRESERVE_HOST=true"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "host_header_forwarding")
	if len(findings) != 0 {
		t.Fatal("non-proxy with host env should not trigger host_header_forwarding")
	}
}

func TestResponseSplittingCRLF(t *testing.T) {
	s := compose.Service{
		Name:        "api",
		Image:       "node:20",
		Environment: []string{"HEADER_SEP=\\r\\n"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "response_splitting_risk")
	if len(findings) == 0 {
		t.Fatal("expected response_splitting_risk for CRLF pattern in env")
	}
	if findings[0].Level != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Level)
	}
}

func TestResponseSplittingURLEncoded(t *testing.T) {
	s := compose.Service{
		Name:        "gateway",
		Image:       "envoy:latest",
		Environment: []string{"INJECT_TEST=%0d%0a"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "response_splitting_risk")
	if len(findings) == 0 {
		t.Fatal("expected response_splitting_risk for URL-encoded CRLF")
	}
}

func TestNoResponseSplittingCleanEnv(t *testing.T) {
	s := compose.Service{
		Name:        "web",
		Image:       "nginx:latest",
		Environment: []string{"LOG_FORMAT=json", "PORT=8080"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "response_splitting_risk")
	if len(findings) != 0 {
		t.Fatal("clean env should not trigger response_splitting_risk")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestSummaryCountsCorrect(t *testing.T) {
	s := compose.Service{
		Name:        "proxy",
		Image:       "nginx:1.25",
		Environment: []string{"ACCESS-CONTROL-ALLOW-ORIGIN: *", "X-CUSTOM-AUTH=token"},
	}
	r := Analyze(collected(s))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings")
	}
	if r.Summary.InsecureCORSHeaders == 0 {
		t.Fatal("expected insecure_cors_headers count > 0")
	}
}

func TestFormatTextHeader(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx:latest")))
	text := FormatText(r)
	if !strings.Contains(text, "HTTP Header Injection Analysis") {
		t.Fatal("FormatText missing header")
	}
}

func TestFormatTextServiceName(t *testing.T) {
	s := compose.Service{
		Name:        "my-proxy",
		Image:       "nginx:latest",
		Environment: []string{"CORS_ALLOW_ALL=true"},
	}
	r := Analyze(collected(s))
	text := FormatText(r)
	if !strings.Contains(text, "my-proxy") {
		t.Fatal("FormatText missing service name")
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := &collect.Collected{
		Root: "/multi",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{svc("web", "nginx:latest")}},
			{Path: "docker-compose.dev.yml", Services: []compose.Service{svc("api", "node:20")}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}
