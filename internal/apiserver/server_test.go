package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestHealthEndpoint(t *testing.T) {
	srv := NewServer(".", 8080, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", w.Code)
	}
	var resp APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q, want ok", resp.Status)
	}
}

func TestCORSHeaders(t *testing.T) {
	srv := NewServer(".", 8080, false)
	srv.CORSOrigin = "https://example.com"
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("CORS origin = %q, want https://example.com", got)
	}
}

func TestCORSPreflight(t *testing.T) {
	srv := NewServer(".", 8080, false)
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("OPTIONS status = %d, want 200", w.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv := NewServer(".", 8080, false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", w.Code)
	}
}

func TestRulesEndpoint(t *testing.T) {
	srv := NewServer(".", 8080, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("rules status = %d, want 200", w.Code)
	}
	var resp APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q, want ok", resp.Status)
	}
}

func TestScanEndpoint(t *testing.T) {
	srv := NewServer(t.TempDir(), 8080, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("scan status = %d, want 200", w.Code)
	}
	var resp APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q, want ok", resp.Status)
	}
}

func TestStatsEndpoint(t *testing.T) {
	srv := NewServer(t.TempDir(), 8080, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("stats status = %d, want 200", w.Code)
	}
}

func TestFindingsEndpoint(t *testing.T) {
	srv := NewServer(t.TempDir(), 8080, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("findings status = %d, want 200", w.Code)
	}
}

func TestFindingsFilterBySeverity(t *testing.T) {
	srv := NewServer(t.TempDir(), 8080, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings?severity=critical", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("findings filter status = %d, want 200", w.Code)
	}
}

func TestFindingsFilterByRule(t *testing.T) {
	srv := NewServer(t.TempDir(), 8080, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings?rule=exposed_inference", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("findings filter status = %d, want 200", w.Code)
	}
}

func TestNewServer(t *testing.T) {
	srv := NewServer("/tmp/test", 9090, true)
	if srv.ScanPath != "/tmp/test" {
		t.Errorf("ScanPath = %q, want /tmp/test", srv.ScanPath)
	}
	if srv.Port != 9090 {
		t.Errorf("Port = %d, want 9090", srv.Port)
	}
	if !srv.Recursive {
		t.Error("Recursive should be true")
	}
}

func TestCountBySeverity(t *testing.T) {
	findings := []rules.Finding{
		{Severity: "high"},
		{Severity: "high"},
		{Severity: "low"},
	}
	m := countBySeverity(findings)
	if m["high"] != 2 {
		t.Errorf("high = %d, want 2", m["high"])
	}
	if m["low"] != 1 {
		t.Errorf("low = %d, want 1", m["low"])
	}
}
