package surrealdbaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name, image string, env []string, ports []compose.PortMapping) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports}
}

func svcCmd(name, image string, env []string, ports []compose.PortMapping, cmd []string) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports, Command: cmd}
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

func TestIsSurrealDBImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"surrealdb/surrealdb:v1.0", true},
		{"surrealdb:latest", true},
		{"nginx:latest", false},
		{"SURREALDB:latest", true},
	}
	for _, tt := range tests {
		if got := isSurrealDBImage(tt.image); got != tt.want {
			t.Errorf("isSurrealDBImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoAuth(t *testing.T) {
	r := Analyze(col(svc("db", "surrealdb/surrealdb:v1.0", nil, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected surrealdb_no_auth finding")
	}
}

func TestAuthViaEnv(t *testing.T) {
	r := Analyze(col(svc("db", "surrealdb/surrealdb:v1.0",
		[]string{"SURREAL_USER=admin", "SURREAL_PASS=s3cur3P@ss!"}, nil)))
	if r.Summary.NoAuth != 0 {
		t.Error("expected no surrealdb_no_auth finding when credentials set")
	}
}

func TestAuthViaCommand(t *testing.T) {
	r := Analyze(col(svcCmd("db", "surrealdb/surrealdb:v1.0", nil, nil,
		[]string{"start", "--user", "root", "--pass", "s3cur3!"})))
	if r.Summary.NoAuth != 0 {
		t.Error("expected no surrealdb_no_auth finding when auth in command")
	}
}

func TestDefaultPassword(t *testing.T) {
	r := Analyze(col(svc("db", "surrealdb/surrealdb:v1.0",
		[]string{"SURREAL_USER=root", "SURREAL_PASS=root"}, nil)))
	if r.Summary.DefaultPassword == 0 {
		t.Error("expected surrealdb_default_password finding")
	}
}

func TestStrongPassword(t *testing.T) {
	r := Analyze(col(svc("db", "surrealdb/surrealdb:v1.0",
		[]string{"SURREAL_USER=admin", "SURREAL_PASS=s3cur3P@ss!"}, nil)))
	if r.Summary.DefaultPassword != 0 {
		t.Error("expected no surrealdb_default_password finding with strong password")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("db", "surrealdb/surrealdb:v1.0", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected surrealdb_no_tls finding")
	}
}

func TestTLSViaEnv(t *testing.T) {
	r := Analyze(col(svc("db", "surrealdb/surrealdb:v1.0",
		[]string{"SURREAL_WEB_CRT=/certs/cert.pem", "SURREAL_WEB_KEY=/certs/key.pem"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no surrealdb_no_tls finding when TLS configured")
	}
}

func TestTLSViaCommand(t *testing.T) {
	r := Analyze(col(svcCmd("db", "surrealdb/surrealdb:v1.0", nil, nil,
		[]string{"start", "--web-crt", "/certs/cert.pem", "--web-key", "/certs/key.pem"})))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no surrealdb_no_tls finding when TLS in command")
	}
}

func TestExposedHTTPPort(t *testing.T) {
	r := Analyze(col(svc("db", "surrealdb/surrealdb:v1.0", nil, []compose.PortMapping{allIf(8000)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected surrealdb_exposed_port finding for 8000")
	}
}

func TestStrictModeDisabled(t *testing.T) {
	r := Analyze(col(svc("db", "surrealdb/surrealdb:v1.0",
		[]string{"SURREAL_USER=admin", "SURREAL_PASS=s3cur3!", "SURREAL_STRICT=false"}, nil)))
	if r.Summary.StrictMode == 0 {
		t.Error("expected surrealdb_strict_mode finding")
	}
}

func TestStrictModeDisabledViaCommand(t *testing.T) {
	r := Analyze(col(svcCmd("db", "surrealdb/surrealdb:v1.0",
		[]string{"SURREAL_USER=admin", "SURREAL_PASS=s3cur3!"},
		nil,
		[]string{"start", "--no-strict"})))
	if r.Summary.StrictMode == 0 {
		t.Error("expected surrealdb_strict_mode finding via command")
	}
}

func TestNonSurrealDBSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("db", "surrealdb/surrealdb:v1.0", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "SurrealDB Security Audit") {
		t.Error("missing title")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No SurrealDB services found") {
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
		svc("db1", "surrealdb/surrealdb:v1.0", nil, nil),
		svc("db2", "surrealdb:latest", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}
