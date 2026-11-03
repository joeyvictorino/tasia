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

func localIf(target int) compose.PortMapping {
	return compose.PortMapping{HostPort: target, TargetPort: target, HostIP: "127.0.0.1"}
}

func col(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func colPath(path string, svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: path, ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func TestIsInfluxImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"influxdb:2.7", true},
		{"bitnami/influxdb:latest", true},
		{"quay.io/influxdb:1.8", true},
		{"redis:7", false},
		{"nginx", false},
	}
	for _, tt := range tests {
		if got := isInfluxImage(tt.image); got != tt.want {
			t.Errorf("isInfluxImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoAuth(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", nil, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected influxdb_no_auth finding")
	}
}

func TestAuthConfigured(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"INFLUXDB_HTTP_AUTH_ENABLED=true"}, nil)))
	if r.Summary.NoAuth != 0 {
		t.Error("should not flag when auth enabled")
	}
}

func TestAuthDisabled(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"INFLUXDB_HTTP_AUTH_ENABLED=false"}, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected no_auth when auth explicitly disabled")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected influxdb_no_tls finding")
	}
}

func TestTLSConfigured(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"INFLUXDB_HTTP_HTTPS_ENABLED=TRUE"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("should not flag when TLS enabled")
	}
}

func TestExposedPort(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", nil, []compose.PortMapping{allIf(8086)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected exposed_port for HTTP API")
	}
}

func TestLocalhostPort(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", nil, []compose.PortMapping{localIf(8086)})))
	if r.Summary.ExposedPort != 0 {
		t.Error("localhost port should not be flagged")
	}
}

func TestRPCPort(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", nil, []compose.PortMapping{allIf(8088)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected exposed_port for RPC port")
	}
}

func TestDefaultPassword(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"INFLUXDB_ADMIN_PASSWORD=admin"}, nil)))
	if r.Summary.DefaultPassword == 0 {
		t.Error("expected default_password finding")
	}
}

func TestStrongPassword(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"INFLUXDB_ADMIN_PASSWORD=x9Kp!mQ2vL"}, nil)))
	if r.Summary.DefaultPassword != 0 {
		t.Error("strong password should not be flagged")
	}
}

func TestWeakToken(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"DOCKER_INFLUXDB_INIT_ADMIN_TOKEN=admin"}, nil)))
	if r.Summary.TokenExposed == 0 {
		t.Error("expected token_exposed finding")
	}
}

func TestStrongToken(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"DOCKER_INFLUXDB_INIT_ADMIN_TOKEN=aB3cD9xYz2mKpQ7"}, nil)))
	if r.Summary.TokenExposed != 0 {
		t.Error("strong token should not be flagged")
	}
}

func TestDebugEnabled(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", []string{"INFLUXDB_LOGGING_LEVEL=debug"}, nil)))
	if r.Summary.DebugEnabled == 0 {
		t.Error("expected debug_enabled finding")
	}
}

func TestNonInfluxSkipped(t *testing.T) {
	r := Analyze(col(svc("redis", "redis:7", nil, nil)))
	if len(r.Services) != 0 {
		t.Error("non-influx service should be ignored")
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

func TestMultiplePorts(t *testing.T) {
	r := Analyze(col(svc("db", "influxdb:2", nil, []compose.PortMapping{allIf(8086), allIf(8088)})))
	if r.Summary.ExposedPort != 2 {
		t.Errorf("expected 2 port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("db", "influxdb:2", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "InfluxDB Security Audit") {
		t.Error("missing title")
	}
	if !strings.Contains(text, "/test") {
		t.Error("missing path")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No InfluxDB services found") {
		t.Error("expected empty message")
	}
}

func TestReportPath(t *testing.T) {
	r := Analyze(colPath("/mydir"))
	if r.Path != "/mydir" {
		t.Errorf("expected /mydir, got %s", r.Path)
	}
}
