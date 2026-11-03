package proxyconfig

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	cf := compose.File{Path: "docker-compose.yml", Services: services}
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{cf}}
}

func findRule(results []ServiceResult, rule string) bool {
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return true
			}
		}
	}
	return false
}

func TestOpenProxyAllInterfaces(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "nginx",
		Command: []string{"nginx", "-c", "proxy_pass http://0.0.0.0:8080/api"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "proxy_open") {
		t.Error("expected proxy_open for binding to 0.0.0.0")
	}
}

func TestOpenProxyWildcard(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"proxy_pass http://*"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "proxy_open") {
		t.Error("expected proxy_open for wildcard binding")
	}
}

func TestNoOpenProxy(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"proxy_pass", "http://backend:8080"},
	})
	r := Analyze(c)
	if findRule(r.Services, "proxy_open") {
		t.Error("should not flag non-wildcard proxy")
	}
}

func TestInsecureUpstream(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "proxy",
		Environment: []string{"BACKEND_URL=upstream_url=http://internal-api:3000"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "proxy_insecure_upstream") {
		t.Error("expected proxy_insecure_upstream for HTTP upstream")
	}
}

func TestSecureUpstreamSuppressed(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "proxy",
		Environment: []string{"BACKEND_URL=upstream_url=http://internal:3000", "TLS=https://secure"},
	})
	r := Analyze(c)
	if findRule(r.Services, "proxy_insecure_upstream") {
		t.Error("should not flag insecure upstream when https is also present")
	}
}

func TestInsecureUpstreamNoHTTPS(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "proxy",
		Environment: []string{"BACKEND_URL=upstream_url=http://internal:3000"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "proxy_insecure_upstream") {
		t.Error("expected proxy_insecure_upstream when only http present")
	}
}

func TestProxyAuthLeak(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"proxy_set_header authorization $http_authorization"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "proxy_auth_leak") {
		t.Error("expected proxy_auth_leak for forwarding authorization header")
	}
}

func TestProxyAuthLeakCookie(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"proxy_set_header Cookie $http_cookie"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "proxy_auth_leak") {
		t.Error("expected proxy_auth_leak for forwarding cookie header")
	}
}

func TestNoProxyAuthLeak(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"proxy_set_header", "X-Request-Id", "abc123"},
	})
	r := Analyze(c)
	if findRule(r.Services, "proxy_auth_leak") {
		t.Error("should not flag non-sensitive headers")
	}
}

func TestSSRFDynamicTarget(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"proxy_pass $upstream_url"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "proxy_ssrf") {
		t.Error("expected proxy_ssrf for dynamic proxy target")
	}
}

func TestSSRFBraceExpansion(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"proxy_pass ${BACKEND_HOST}:${BACKEND_PORT}"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "proxy_ssrf") {
		t.Error("expected proxy_ssrf for brace expansion in proxy target")
	}
}

func TestNoSSRF(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"proxy_pass", "http://backend:8080"},
	})
	r := Analyze(c)
	if findRule(r.Services, "proxy_ssrf") {
		t.Error("should not flag static proxy target")
	}
}

func TestHeaderInjection(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"proxy_set_header Host $host"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "proxy_header_injection") {
		t.Error("expected proxy_header_injection for variable in host header")
	}
}

func TestNoHeaderInjection(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"proxy_set_header", "Host", "backend.local"},
	})
	r := Analyze(c)
	if findRule(r.Services, "proxy_header_injection") {
		t.Error("should not flag static header value")
	}
}

func TestMissingTLS(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "proxy",
		Environment: []string{"SSL_VERIFY=ssl_verify off"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "proxy_missing_tls") {
		t.Error("expected proxy_missing_tls when TLS verification disabled")
	}
}

func TestMissingTLSSkipVerify(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "proxy",
		Environment: []string{"TLS_OPTS=tls_skip_verify=true"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "proxy_missing_tls") {
		t.Error("expected proxy_missing_tls for tls_skip_verify")
	}
}

func TestNoMissingTLS(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"nginx", "-g", "daemon off;"},
	})
	r := Analyze(c)
	if findRule(r.Services, "proxy_missing_tls") {
		t.Error("should not flag service without TLS issues")
	}
}

func TestMultipleFindings(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "danger-proxy",
		Command:     []string{"proxy_pass $upstream_url", "proxy_set_header authorization $http_auth"},
		Environment: []string{"SSL=ssl_verify off"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "proxy",
		Command: []string{"proxy_pass $upstream"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Proxy Configuration") {
		t.Error("expected 'Proxy Configuration' in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "no findings") {
		t.Error("expected 'no findings' in output")
	}
}

func TestReportPath(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Path != "/test" {
		t.Errorf("expected path /test, got %s", r.Path)
	}
}

func TestEnvVarSource(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "proxy",
		Environment: []string{"PROXY_CONFIG=proxy_pass http://0.0.0.0:9090/all"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "proxy_open") {
		t.Error("expected proxy_open from environment variable content")
	}
}

func TestLabelSource(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:   "proxy",
		Labels: map[string]string{"traefik.backend": "proxy_pass http://0.0.0.0:80"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "proxy_open") {
		t.Error("expected proxy_open from label content")
	}
}
