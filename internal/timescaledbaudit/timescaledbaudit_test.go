package timescaledbaudit

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

func TestIsTimescaleDBImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"timescale/timescaledb:latest-pg16", true},
		{"timescaledb:2.13", true},
		{"TIMESCALE/TIMESCALEDB:latest", true},
		{"postgres:16", false},
		{"nginx:latest", false},
	}
	for _, tt := range tests {
		if got := isTimescaleDBImage(tt.image); got != tt.want {
			t.Errorf("isTimescaleDBImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoAuth(t *testing.T) {
	r := Analyze(col(svc("ts", "timescale/timescaledb:latest-pg16", nil, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected timescaledb_no_auth finding when no password set")
	}
}

func TestAuthViaPassword(t *testing.T) {
	r := Analyze(col(svc("ts", "timescale/timescaledb:latest-pg16",
		[]string{"POSTGRES_PASSWORD=s3cur3P@ss!"}, nil)))
	if r.Summary.NoAuth != 0 {
		t.Error("expected no timescaledb_no_auth finding when password set")
	}
}

func TestAuthViaPasswordFile(t *testing.T) {
	r := Analyze(col(svc("ts", "timescale/timescaledb:latest-pg16",
		[]string{"POSTGRES_PASSWORD_FILE=/run/secrets/pg_pass"}, nil)))
	if r.Summary.NoAuth != 0 {
		t.Error("expected no timescaledb_no_auth finding when password file set")
	}
}

func TestTrustAuth(t *testing.T) {
	r := Analyze(col(svc("ts", "timescale/timescaledb:latest-pg16",
		[]string{"POSTGRES_HOST_AUTH_METHOD=trust"}, nil)))
	if r.Summary.TrustAuth == 0 {
		t.Error("expected timescaledb_trust_auth finding")
	}
	if r.Summary.NoAuth != 0 {
		t.Error("trust auth should not also trigger no_auth")
	}
}

func TestDefaultPassword(t *testing.T) {
	r := Analyze(col(svc("ts", "timescale/timescaledb:latest-pg16",
		[]string{"POSTGRES_PASSWORD=postgres"}, nil)))
	if r.Summary.DefaultPassword == 0 {
		t.Error("expected timescaledb_default_password finding")
	}
}

func TestStrongPassword(t *testing.T) {
	r := Analyze(col(svc("ts", "timescale/timescaledb:latest-pg16",
		[]string{"POSTGRES_PASSWORD=s3cur3P@ss!"}, nil)))
	if r.Summary.DefaultPassword != 0 {
		t.Error("expected no default_password finding with strong password")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("ts", "timescale/timescaledb:latest-pg16", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected timescaledb_no_tls finding")
	}
}

func TestTLSEnabled(t *testing.T) {
	r := Analyze(col(svc("ts", "timescale/timescaledb:latest-pg16",
		[]string{"POSTGRES_PASSWORD=s3cur3!", "POSTGRES_SSL=on"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no timescaledb_no_tls finding when SSL on")
	}
}

func TestTLSViaPGSSLMode(t *testing.T) {
	r := Analyze(col(svc("ts", "timescale/timescaledb:latest-pg16",
		[]string{"POSTGRES_PASSWORD=s3cur3!", "PGSSLMODE=require"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no timescaledb_no_tls finding when PGSSLMODE=require")
	}
}

func TestExposedPort(t *testing.T) {
	r := Analyze(col(svc("ts", "timescale/timescaledb:latest-pg16", nil, []compose.PortMapping{allIf(5432)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected timescaledb_exposed_port finding for 5432")
	}
}

func TestNonTimescaleSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestPostgresNotMatched(t *testing.T) {
	r := Analyze(col(svc("pg", "postgres:16", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services for plain postgres, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("ts", "timescale/timescaledb:latest-pg16", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "TimescaleDB Security Audit") {
		t.Error("missing title")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No TimescaleDB services found") {
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
		svc("ts1", "timescale/timescaledb:latest-pg16", nil, nil),
		svc("ts2", "timescaledb:2.13", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}
