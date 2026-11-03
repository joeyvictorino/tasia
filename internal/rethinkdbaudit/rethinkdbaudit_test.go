package rethinkdbaudit

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

func TestIsRethinkDBImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"rethinkdb:2.4", true},
		{"bitnami/rethinkdb:latest", true},
		{"nginx:latest", false},
		{"RETHINKDB:latest", true},
	}
	for _, tt := range tests {
		if got := isRethinkDBImage(tt.image); got != tt.want {
			t.Errorf("isRethinkDBImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoAuth(t *testing.T) {
	r := Analyze(col(svc("db", "rethinkdb:2", nil, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected rethinkdb_no_auth finding")
	}
}

func TestAuthEnabled(t *testing.T) {
	r := Analyze(col(svc("db", "rethinkdb:2",
		[]string{"RETHINKDB_PASSWORD=s3cur3P@ss!"}, nil)))
	if r.Summary.NoAuth != 0 {
		t.Error("expected no rethinkdb_no_auth finding when password set")
	}
}

func TestDefaultPassword(t *testing.T) {
	r := Analyze(col(svc("db", "rethinkdb:2",
		[]string{"RETHINKDB_PASSWORD=admin"}, nil)))
	if r.Summary.DefaultPassword == 0 {
		t.Error("expected rethinkdb_default_password finding")
	}
}

func TestStrongPassword(t *testing.T) {
	r := Analyze(col(svc("db", "rethinkdb:2",
		[]string{"RETHINKDB_PASSWORD=s3cur3P@ss!"}, nil)))
	if r.Summary.DefaultPassword != 0 {
		t.Error("expected no rethinkdb_default_password finding with strong password")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("db", "rethinkdb:2", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected rethinkdb_no_tls finding")
	}
}

func TestTLSEnabled(t *testing.T) {
	r := Analyze(col(svc("db", "rethinkdb:2",
		[]string{"RETHINKDB_TLS_CERT=/certs/cert.pem", "RETHINKDB_PASSWORD=s3cur3!"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no rethinkdb_no_tls finding when TLS enabled")
	}
}

func TestExposedClientPort(t *testing.T) {
	r := Analyze(col(svc("db", "rethinkdb:2", nil, []compose.PortMapping{allIf(28015)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected rethinkdb_exposed_port finding for 28015")
	}
}

func TestExposedClusterPort(t *testing.T) {
	r := Analyze(col(svc("db", "rethinkdb:2", nil, []compose.PortMapping{allIf(29015)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected rethinkdb_exposed_port finding for 29015")
	}
}

func TestExposedWebUIPort(t *testing.T) {
	r := Analyze(col(svc("db", "rethinkdb:2", nil, []compose.PortMapping{allIf(8080)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected rethinkdb_exposed_port finding for 8080")
	}
}

func TestMultiplePortsExposed(t *testing.T) {
	r := Analyze(col(svc("db", "rethinkdb:2", nil,
		[]compose.PortMapping{allIf(28015), allIf(29015), allIf(8080)})))
	if r.Summary.ExposedPort != 3 {
		t.Errorf("expected 3 port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestWebUIExposedWithoutAuth(t *testing.T) {
	r := Analyze(col(svc("db", "rethinkdb:2", nil,
		[]compose.PortMapping{allIf(8080)})))
	if r.Summary.WebUIExposed == 0 {
		t.Error("expected rethinkdb_web_ui_exposed finding")
	}
}

func TestWebUINotExposedWithAuth(t *testing.T) {
	r := Analyze(col(svc("db", "rethinkdb:2",
		[]string{"RETHINKDB_PASSWORD=s3cur3!"},
		[]compose.PortMapping{allIf(8080)})))
	if r.Summary.WebUIExposed != 0 {
		t.Error("expected no web_ui_exposed finding when auth enabled")
	}
}

func TestNonRethinkDBSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("db", "rethinkdb:2", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "RethinkDB Security Audit") {
		t.Error("missing title")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No RethinkDB services found") {
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
		svc("db1", "rethinkdb:2", nil, nil),
		svc("db2", "bitnami/rethinkdb", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}
