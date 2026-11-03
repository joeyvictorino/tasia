package qdrantaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name, image string, env []string, ports []compose.PortMapping) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports}
}

func allIf(target int) compose.PortMapping {
	return compose.PortMapping{HostPort: target, TargetPort: target, HostIP: "0.0.0.0"}
}

func col(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func colPath(path string, svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: path, ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func TestIsQdrantImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"qdrant/qdrant:latest", true},
		{"qdrant/qdrant:v1.7.4", true},
		{"qdrant:latest", true},
		{"nginx:latest", false},
		{"QDRANT/QDRANT:latest", true},
	}
	for _, tt := range tests {
		if got := isQdrantImage(tt.image); got != tt.want {
			t.Errorf("isQdrantImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoAPIKey(t *testing.T) {
	r := Analyze(col(svc("vec", "qdrant/qdrant:latest", nil, nil)))
	if r.Summary.NoAPIKey == 0 {
		t.Error("expected qdrant_no_api_key finding when no API key set")
	}
}

func TestAPIKeySet(t *testing.T) {
	r := Analyze(col(svc("vec", "qdrant/qdrant:latest",
		[]string{"QDRANT__SERVICE__API_KEY=mysecretkey123"}, nil)))
	if r.Summary.NoAPIKey != 0 {
		t.Error("expected no qdrant_no_api_key finding when API key set")
	}
}

func TestAPIKeyAltEnv(t *testing.T) {
	r := Analyze(col(svc("vec", "qdrant/qdrant:latest",
		[]string{"QDRANT_API_KEY=mysecretkey123"}, nil)))
	if r.Summary.NoAPIKey != 0 {
		t.Error("expected no qdrant_no_api_key finding when alt API key env set")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("vec", "qdrant/qdrant:latest", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected qdrant_no_tls finding")
	}
}

func TestTLSEnabled(t *testing.T) {
	r := Analyze(col(svc("vec", "qdrant/qdrant:latest",
		[]string{"QDRANT__TLS__CERT=/certs/cert.pem", "QDRANT__SERVICE__API_KEY=key"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no qdrant_no_tls finding when TLS cert set")
	}
}

func TestExposedHTTPPort(t *testing.T) {
	r := Analyze(col(svc("vec", "qdrant/qdrant:latest", nil, []compose.PortMapping{allIf(6333)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected qdrant_exposed_port finding for 6333")
	}
}

func TestExposedGRPCPort(t *testing.T) {
	r := Analyze(col(svc("vec", "qdrant/qdrant:latest", nil, []compose.PortMapping{allIf(6334)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected qdrant_exposed_port finding for 6334")
	}
}

func TestBothPortsExposed(t *testing.T) {
	r := Analyze(col(svc("vec", "qdrant/qdrant:latest", nil,
		[]compose.PortMapping{allIf(6333), allIf(6334)})))
	if r.Summary.ExposedPort != 2 {
		t.Errorf("expected 2 port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestDebugMode(t *testing.T) {
	r := Analyze(col(svc("vec", "qdrant/qdrant:latest",
		[]string{"QDRANT__SERVICE__API_KEY=key", "QDRANT__LOG_LEVEL=debug"}, nil)))
	if r.Summary.DebugMode == 0 {
		t.Error("expected qdrant_debug_mode finding")
	}
}

func TestTraceMode(t *testing.T) {
	r := Analyze(col(svc("vec", "qdrant/qdrant:latest",
		[]string{"QDRANT__SERVICE__API_KEY=key", "QDRANT__LOG_LEVEL=trace"}, nil)))
	if r.Summary.DebugMode == 0 {
		t.Error("expected qdrant_debug_mode finding for trace level")
	}
}

func TestRustLogDebug(t *testing.T) {
	r := Analyze(col(svc("vec", "qdrant/qdrant:latest",
		[]string{"QDRANT__SERVICE__API_KEY=key", "RUST_LOG=debug"}, nil)))
	if r.Summary.DebugMode == 0 {
		t.Error("expected qdrant_debug_mode finding for RUST_LOG=debug")
	}
}

func TestNoDebugMode(t *testing.T) {
	r := Analyze(col(svc("vec", "qdrant/qdrant:latest",
		[]string{"QDRANT__SERVICE__API_KEY=key"}, nil)))
	if r.Summary.DebugMode != 0 {
		t.Error("expected no debug_mode finding when not in debug")
	}
}

func TestNonQdrantSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("vec", "qdrant/qdrant:latest", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "Qdrant Security Audit") {
		t.Error("missing title")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No Qdrant services found") {
		t.Error("expected empty message")
	}
}

func TestEmptyCollection(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	if len(r.Services) != 0 {
		t.Error("expected empty report")
	}
}

func TestReportPath(t *testing.T) {
	r := Analyze(colPath("/mydir"))
	if r.Path != "/mydir" {
		t.Errorf("expected /mydir, got %s", r.Path)
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(col(
		svc("vec1", "qdrant/qdrant:latest", nil, nil),
		svc("vec2", "qdrant:v1.7", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}
