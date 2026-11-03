package milvusaudit

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

func TestIsMilvusImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"milvusdb/milvus:v2.3", true},
		{"milvus:latest", true},
		{"bitnami/milvus:latest", true},
		{"nginx:latest", false},
		{"MILVUSDB/MILVUS:latest", true},
	}
	for _, tt := range tests {
		if got := isMilvusImage(tt.image); got != tt.want {
			t.Errorf("isMilvusImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoAuth(t *testing.T) {
	r := Analyze(col(svc("vec", "milvusdb/milvus:v2.3", nil, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected milvus_no_auth finding")
	}
}

func TestAuthEnabled(t *testing.T) {
	r := Analyze(col(svc("vec", "milvusdb/milvus:v2.3",
		[]string{"MILVUS_AUTH_ENABLED=true"}, nil)))
	if r.Summary.NoAuth != 0 {
		t.Error("expected no milvus_no_auth finding when auth enabled")
	}
}

func TestAuthViaToken(t *testing.T) {
	r := Analyze(col(svc("vec", "milvusdb/milvus:v2.3",
		[]string{"MILVUS_TOKEN=s3cur3T0ken!"}, nil)))
	if r.Summary.NoAuth != 0 {
		t.Error("expected no milvus_no_auth finding when token set")
	}
}

func TestDefaultPassword(t *testing.T) {
	r := Analyze(col(svc("vec", "milvusdb/milvus:v2.3",
		[]string{"MILVUS_ROOT_PASSWORD=milvus"}, nil)))
	if r.Summary.DefaultPassword == 0 {
		t.Error("expected milvus_default_password finding")
	}
}

func TestStrongPassword(t *testing.T) {
	r := Analyze(col(svc("vec", "milvusdb/milvus:v2.3",
		[]string{"MILVUS_ROOT_PASSWORD=s3cur3P@ss!"}, nil)))
	if r.Summary.DefaultPassword != 0 {
		t.Error("expected no milvus_default_password finding with strong password")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("vec", "milvusdb/milvus:v2.3", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected milvus_no_tls finding")
	}
}

func TestTLSEnabled(t *testing.T) {
	r := Analyze(col(svc("vec", "milvusdb/milvus:v2.3",
		[]string{"MILVUS_TLS_ENABLED=true"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no milvus_no_tls finding when TLS enabled")
	}
}

func TestExposedGRPCPort(t *testing.T) {
	r := Analyze(col(svc("vec", "milvusdb/milvus:v2.3", nil, []compose.PortMapping{allIf(19530)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected milvus_exposed_port finding for 19530")
	}
}

func TestExposedMetricsPort(t *testing.T) {
	r := Analyze(col(svc("vec", "milvusdb/milvus:v2.3", nil, []compose.PortMapping{allIf(9091)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected milvus_exposed_port finding for 9091")
	}
}

func TestMultiplePortsExposed(t *testing.T) {
	r := Analyze(col(svc("vec", "milvusdb/milvus:v2.3", nil,
		[]compose.PortMapping{allIf(19530), allIf(9091), allIf(19121)})))
	if r.Summary.ExposedPort != 3 {
		t.Errorf("expected 3 port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestNonMilvusSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("vec", "milvusdb/milvus:v2.3", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "Milvus Security Audit") {
		t.Error("missing title")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No Milvus services found") {
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
		svc("vec1", "milvusdb/milvus:v2.3", nil, nil),
		svc("vec2", "milvus:latest", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}
