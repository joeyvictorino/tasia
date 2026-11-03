package scylladbaudit

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

func TestIsScyllaDBImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"scylladb/scylla:5.2", true},
		{"scylladb/scylla-enterprise:latest", true},
		{"nginx:latest", false},
		{"SCYLLADB/SCYLLA:latest", true},
		{"cassandra:4", false},
	}
	for _, tt := range tests {
		if got := isScyllaDBImage(tt.image); got != tt.want {
			t.Errorf("isScyllaDBImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoAuth(t *testing.T) {
	r := Analyze(col(svc("db", "scylladb/scylla:5", nil, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected scylladb_no_auth finding")
	}
}

func TestAuthEnabled(t *testing.T) {
	r := Analyze(col(svc("db", "scylladb/scylla:5",
		[]string{"CASSANDRA_PASSWORD=s3cur3P@ss!"}, nil)))
	if r.Summary.NoAuth != 0 {
		t.Error("expected no scylladb_no_auth finding when password set")
	}
}

func TestAuthViaAuthenticator(t *testing.T) {
	r := Analyze(col(svc("db", "scylladb/scylla:5",
		[]string{"SCYLLA_AUTHENTICATOR=PasswordAuthenticator"}, nil)))
	if r.Summary.NoAuth != 0 {
		t.Error("expected no scylladb_no_auth finding when authenticator set")
	}
}

func TestAuthDisabledAllowAll(t *testing.T) {
	r := Analyze(col(svc("db", "scylladb/scylla:5",
		[]string{"SCYLLA_AUTHENTICATOR=AllowAllAuthenticator"}, nil)))
	if r.Summary.AuthDisabled == 0 {
		t.Error("expected scylladb_auth_disabled finding")
	}
}

func TestDefaultPassword(t *testing.T) {
	r := Analyze(col(svc("db", "scylladb/scylla:5",
		[]string{"CASSANDRA_PASSWORD=cassandra"}, nil)))
	if r.Summary.DefaultPassword == 0 {
		t.Error("expected scylladb_default_password finding")
	}
}

func TestStrongPassword(t *testing.T) {
	r := Analyze(col(svc("db", "scylladb/scylla:5",
		[]string{"CASSANDRA_PASSWORD=s3cur3P@ss!"}, nil)))
	if r.Summary.DefaultPassword != 0 {
		t.Error("expected no scylladb_default_password finding with strong password")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("db", "scylladb/scylla:5", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected scylladb_no_tls finding")
	}
}

func TestTLSEnabled(t *testing.T) {
	r := Analyze(col(svc("db", "scylladb/scylla:5",
		[]string{"SCYLLA_SSL_CERT=/certs/cert.pem", "CASSANDRA_PASSWORD=s3cur3!"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no scylladb_no_tls finding when TLS enabled")
	}
}

func TestExposedCQLPort(t *testing.T) {
	r := Analyze(col(svc("db", "scylladb/scylla:5", nil, []compose.PortMapping{allIf(9042)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected scylladb_exposed_port finding for 9042")
	}
}

func TestExposedInterNodePort(t *testing.T) {
	r := Analyze(col(svc("db", "scylladb/scylla:5", nil, []compose.PortMapping{allIf(7000)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected scylladb_exposed_port finding for 7000")
	}
}

func TestExposedJMXPort(t *testing.T) {
	r := Analyze(col(svc("db", "scylladb/scylla:5", nil, []compose.PortMapping{allIf(7199)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected scylladb_exposed_port finding for 7199")
	}
}

func TestExposedRESTAPIPort(t *testing.T) {
	r := Analyze(col(svc("db", "scylladb/scylla:5", nil, []compose.PortMapping{allIf(10000)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected scylladb_exposed_port finding for 10000")
	}
}

func TestMultiplePortsExposed(t *testing.T) {
	r := Analyze(col(svc("db", "scylladb/scylla:5", nil,
		[]compose.PortMapping{allIf(9042), allIf(7000), allIf(10000)})))
	if r.Summary.ExposedPort != 3 {
		t.Errorf("expected 3 port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestNonScyllaDBSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("db", "scylladb/scylla:5", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "ScyllaDB Security Audit") {
		t.Error("missing title")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No ScyllaDB services found") {
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
		svc("db1", "scylladb/scylla:5", nil, nil),
		svc("db2", "scylladb/scylla-enterprise:latest", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}
