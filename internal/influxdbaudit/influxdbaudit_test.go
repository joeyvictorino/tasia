package influxdbaudit

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

func TestIsInfluxDBImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"influxdb:2.7", true},
		{"bitnami/influxdb:latest", true},
		{"nginx:latest", false},
		{"INFLUXDB:latest", true},
	}
	for _, tt := range tests {
		if got := isInfluxDBImage(tt.image); got != tt.want {
			t.Errorf("isInfluxDBImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoAuth(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", nil, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected influxdb_no_auth finding")
	}
}

func TestAuthDisabled(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"INFLUXDB_HTTP_AUTH_ENABLED=false"}, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected influxdb_no_auth finding when auth explicitly disabled")
	}
}

func TestAuthEnabled(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"INFLUXDB_HTTP_AUTH_ENABLED=true"}, nil)))
	if r.Summary.NoAuth != 0 {
		t.Error("expected no influxdb_no_auth finding when auth enabled")
	}
}

func TestAuthViaPassword(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"DOCKER_INFLUXDB_INIT_PASSWORD=securepass123"}, nil)))
	if r.Summary.NoAuth != 0 {
		t.Error("expected no influxdb_no_auth finding when password set")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected influxdb_no_tls finding")
	}
}

func TestTLSEnabled(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"INFLUXDB_HTTP_HTTPS_ENABLED=true"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no influxdb_no_tls finding when TLS enabled")
	}
}

func TestExposedAPIPort(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", nil, []compose.PortMapping{allIf(8086)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected influxdb_exposed_port finding for 8086")
	}
}

func TestExposedRPCPort(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", nil, []compose.PortMapping{allIf(8088)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected influxdb_exposed_port finding for 8088")
	}
}

func TestBothPortsExposed(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", nil, []compose.PortMapping{allIf(8086), allIf(8088)})))
	if r.Summary.ExposedPort != 2 {
		t.Errorf("expected 2 port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestDefaultPassword(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"DOCKER_INFLUXDB_INIT_PASSWORD=admin"}, nil)))
	if r.Summary.DefaultPassword == 0 {
		t.Error("expected influxdb_default_password finding")
	}
}

func TestStrongPassword(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"DOCKER_INFLUXDB_INIT_PASSWORD=s3cur3P@ss!"}, nil)))
	if r.Summary.DefaultPassword != 0 {
		t.Error("expected no influxdb_default_password finding with strong password")
	}
}

func TestAdminExposed(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2",
		[]string{"INFLUXDB_HTTP_BIND_ADDRESS=0.0.0.0:8086"},
		[]compose.PortMapping{allIf(8086)})))
	if r.Summary.AdminExposed == 0 {
		t.Error("expected influxdb_admin_exposed finding")
	}
}

func TestAdminNotExposedWithAuth(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2",
		[]string{"INFLUXDB_HTTP_AUTH_ENABLED=true", "INFLUXDB_HTTP_BIND_ADDRESS=0.0.0.0:8086"},
		[]compose.PortMapping{allIf(8086)})))
	if r.Summary.AdminExposed != 0 {
		t.Error("expected no admin_exposed finding when auth enabled")
	}
}

func TestNonInfluxDBSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("db", "influxdb:2", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "InfluxDB Security Audit") {
		t.Error("missing title")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No InfluxDB services found") {
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
		svc("db1", "influxdb:2", nil, nil),
		svc("db2", "bitnami/influxdb", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}
