package corsconfig

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

func TestWildcardOriginCommand(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "api",
		Command: []string{"access-control-allow-origin: *"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cors_wildcard_origin") {
		t.Error("expected cors_wildcard_origin for wildcard in command")
	}
}

func TestWildcardOriginEnv(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "api",
		Environment: []string{"CORS=cors_origin=*"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cors_wildcard_origin") {
		t.Error("expected cors_wildcard_origin from env")
	}
}

func TestNoWildcardOrigin(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "api",
		Environment: []string{"CORS=cors_origin=https://example.com"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cors_wildcard_origin") {
		t.Error("should not flag specific origin")
	}
}

func TestCredentialsWildcard(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "api",
		Environment: []string{"CORS=cors_origin=*", "CREDS=allow_credentials=true"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cors_credentials_wildcard") {
		t.Error("expected cors_credentials_wildcard")
	}
}

func TestCredentialsNoWildcard(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "api",
		Environment: []string{"CORS=cors_origin=https://app.example.com", "CREDS=allow_credentials=true"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cors_credentials_wildcard") {
		t.Error("should not flag credentials without wildcard origin")
	}
}

func TestUnsafeHeaders(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "api",
		Command: []string{"access-control-allow-headers: *"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cors_unsafe_headers") {
		t.Error("expected cors_unsafe_headers for wildcard headers")
	}
}

func TestNoUnsafeHeaders(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "api",
		Command: []string{"access-control-allow-headers: content-type"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cors_unsafe_headers") {
		t.Error("should not flag specific headers")
	}
}

func TestUnsafeMethods(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "api",
		Command: []string{"access-control-allow-methods: *"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cors_unsafe_methods") {
		t.Error("expected cors_unsafe_methods")
	}
}

func TestUnsafeMethodDelete(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "api",
		Command: []string{"access-control-allow-methods: delete"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cors_unsafe_methods") {
		t.Error("expected cors_unsafe_methods for DELETE")
	}
}

func TestNoUnsafeMethods(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "api",
		Command: []string{"access-control-allow-methods:", "get", "post"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cors_unsafe_methods") {
		t.Error("should not flag GET/POST methods")
	}
}

func TestNullOrigin(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "api",
		Command: []string{"access-control-allow-origin: null"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cors_null_origin") {
		t.Error("expected cors_null_origin")
	}
}

func TestNoNullOrigin(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "api",
		Command: []string{"access-control-allow-origin: https://app.example.com"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cors_null_origin") {
		t.Error("should not flag specific origin")
	}
}

func TestMissingCORS(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "api",
		Command: []string{"api server --port 8080"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cors_missing") {
		t.Error("expected cors_missing for API service without CORS")
	}
}

func TestMissingCORSSuppressed(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "api",
		Command:     []string{"api server --port 8080"},
		Environment: []string{"CORS=cors_origin=https://app.example.com"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cors_missing") {
		t.Error("should not flag when CORS is configured")
	}
}

func TestMultipleFindings(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "api",
		Command:     []string{"access-control-allow-origin: *", "access-control-allow-headers: *"},
		Environment: []string{"CREDS=allow_credentials=true"},
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
		Name:    "api",
		Command: []string{"access-control-allow-origin: *"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "CORS Configuration") {
		t.Error("expected 'CORS Configuration' in output")
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

func TestLabelSource(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:   "api",
		Labels: map[string]string{"cors": "access-control-allow-origin: *"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cors_wildcard_origin") {
		t.Error("expected cors_wildcard_origin from label")
	}
}

func TestNullOriginEnv(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "api",
		Environment: []string{"CORS=cors_origin=null"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cors_null_origin") {
		t.Error("expected cors_null_origin from env")
	}
}
