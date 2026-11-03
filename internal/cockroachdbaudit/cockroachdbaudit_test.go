package cockroachdbaudit

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

func TestIsCockroachImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"cockroachdb/cockroach:v23.1", true},
		{"cockroach:latest", true},
		{"CockroachDB/Cockroach:v22.2", true},
		{"nginx:latest", false},
		{"postgres:15", false},
	}
	for _, tt := range tests {
		if got := isCockroachImage(tt.image); got != tt.want {
			t.Errorf("isCockroachImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestInsecureEnv(t *testing.T) {
	r := Analyze(col(svc("db", "cockroachdb/cockroach:v23.1", []string{"COCKROACH_INSECURE=true"}, nil)))
	if r.Summary.Insecure == 0 {
		t.Error("expected cockroachdb_insecure finding")
	}
}

func TestInsecureCommand(t *testing.T) {
	r := Analyze(col(svcCmd("db", "cockroachdb/cockroach:v23.1", nil, nil, []string{"start-single-node", "--insecure"})))
	if r.Summary.Insecure == 0 {
		t.Error("expected cockroachdb_insecure finding from --insecure flag")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("db", "cockroachdb/cockroach:v23.1", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected cockroachdb_no_tls finding")
	}
}

func TestTLSConfigured(t *testing.T) {
	r := Analyze(col(svc("db", "cockroachdb/cockroach:v23.1", []string{"COCKROACH_CERTS_DIR=/custom/certs"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no cockroachdb_no_tls finding when certs configured")
	}
}

func TestTLSViaCommand(t *testing.T) {
	r := Analyze(col(svcCmd("db", "cockroachdb/cockroach:v23.1", nil, nil, []string{"start", "--certs-dir=/certs"})))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no cockroachdb_no_tls when --certs-dir in command")
	}
}

func TestExposedPort(t *testing.T) {
	r := Analyze(col(svc("db", "cockroachdb/cockroach:v23.1", nil, []compose.PortMapping{allIf(26257)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected cockroachdb_exposed_port finding")
	}
}

func TestUIExposedInsecure(t *testing.T) {
	r := Analyze(col(svc("db", "cockroachdb/cockroach:v23.1",
		[]string{"COCKROACH_INSECURE=true"},
		[]compose.PortMapping{allIf(8080)})))
	if r.Summary.UIExposed == 0 {
		t.Error("expected cockroachdb_ui_exposed finding")
	}
}

func TestDefaultCerts(t *testing.T) {
	r := Analyze(col(svc("db", "cockroachdb/cockroach:v23.1",
		[]string{"COCKROACH_CERTS_DIR=/cockroach/cockroach-certs"}, nil)))
	if r.Summary.DefaultCerts == 0 {
		t.Error("expected cockroachdb_default_certs finding")
	}
}

func TestNonCockroachSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestEmptyCollection(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	if len(r.Services) != 0 {
		t.Error("expected empty report")
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(col(svc("db", "cockroachdb/cockroach:v23.1", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "CockroachDB Security Audit") {
		t.Error("missing title")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No CockroachDB services found") {
		t.Error("missing empty message")
	}
}

func TestMultiplePorts(t *testing.T) {
	r := Analyze(col(svc("db", "cockroachdb/cockroach:v23.1", nil,
		[]compose.PortMapping{allIf(26257), allIf(8080)})))
	if r.Summary.ExposedPort != 2 {
		t.Errorf("expected 2 port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestReportPath(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/mydir"})
	if r.Path != "/mydir" {
		t.Errorf("expected /mydir, got %s", r.Path)
	}
}
