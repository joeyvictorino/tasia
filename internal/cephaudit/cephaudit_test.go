package cephaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name, image string, env []string, ports []compose.PortMapping) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports}
}

func allPort(target int) compose.PortMapping {
	return compose.PortMapping{HostPort: target, TargetPort: target, Raw: "0.0.0.0:", HostIP: "0.0.0.0"}
}

func localPort(target int) compose.PortMapping {
	return compose.PortMapping{HostPort: target, TargetPort: target, Raw: "127.0.0.1:", HostIP: "127.0.0.1"}
}

func col(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func colPath(path string, svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: path, ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func TestIsCephImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"ceph/ceph:latest", true},
		{"ceph/daemon:v16", true},
		{"quay.io/ceph/ceph:17", true},
		{"rook/ceph:master", true},
		{"ceph/demo:latest", true},
		{"nginx:latest", false},
		{"postgres:15", false},
	}
	for _, tt := range tests {
		got := isCephImage(tt.image)
		if got != tt.want {
			t.Errorf("isCephImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoAuth(t *testing.T) {
	r := Analyze(col(svc("ceph1", "ceph/ceph", []string{"CEPH_AUTH=none"}, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected no_auth finding")
	}
}

func TestPartialAuth(t *testing.T) {
	r := Analyze(col(svc("ceph1", "ceph/ceph", []string{"auth_cluster_required=none"}, nil)))
	if r.Summary.PartialAuth == 0 {
		t.Error("expected partial_auth finding")
	}
}

func TestNoEncryption(t *testing.T) {
	r := Analyze(col(svc("ceph1", "ceph/daemon", []string{"ms_encrypt=false"}, nil)))
	if r.Summary.NoEncryption == 0 {
		t.Error("expected no_encryption finding")
	}
}

func TestExposedPort(t *testing.T) {
	r := Analyze(col(svc("ceph1", "ceph/ceph", nil, []compose.PortMapping{allPort(6789)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected exposed_port finding")
	}
}

func TestLocalhostPort(t *testing.T) {
	r := Analyze(col(svc("ceph1", "ceph/ceph", nil, []compose.PortMapping{localPort(6789)})))
	if r.Summary.ExposedPort != 0 {
		t.Error("localhost port should not be flagged")
	}
}

func TestDefaultDashboardPassword(t *testing.T) {
	r := Analyze(col(svc("ceph1", "ceph/ceph", []string{"DASHBOARD_PASSWORD=admin"}, nil)))
	if r.Summary.DefaultPassword == 0 {
		t.Error("expected default_password finding")
	}
}

func TestDemoMode(t *testing.T) {
	r := Analyze(col(svc("ceph1", "ceph/demo", []string{"DEMO_MODE=true"}, nil)))
	if r.Summary.DemoMode == 0 {
		t.Error("expected demo_mode finding")
	}
}

func TestDebugEnabled(t *testing.T) {
	r := Analyze(col(svc("ceph1", "ceph/ceph", []string{"DEBUG_OSD=20"}, nil)))
	if r.Summary.DebugEnabled == 0 {
		t.Error("expected debug_enabled finding")
	}
}

func TestCleanService(t *testing.T) {
	r := Analyze(col(svc("ceph1", "ceph/ceph", []string{"CEPH_AUTH=cephx"}, nil)))
	total := r.Summary.NoAuth + r.Summary.PartialAuth + r.Summary.NoEncryption +
		r.Summary.ExposedPort + r.Summary.DefaultPassword + r.Summary.DemoMode + r.Summary.DebugEnabled
	if total != 0 {
		t.Errorf("expected 0 findings, got %d", total)
	}
}

func TestNonCephSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Error("non-ceph service should be ignored")
	}
}

func TestMultiplePorts(t *testing.T) {
	r := Analyze(col(svc("ceph1", "ceph/ceph", nil, []compose.PortMapping{allPort(6789), allPort(3300), allPort(7480)})))
	if r.Summary.ExposedPort != 3 {
		t.Errorf("expected 3 exposed port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(col(
		svc("mon", "ceph/ceph", []string{"CEPH_AUTH=none"}, nil),
		svc("osd", "ceph/daemon", []string{"ms_encrypt=false"}, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}

func TestRookCeph(t *testing.T) {
	r := Analyze(col(svc("rook", "rook/ceph:latest", nil, nil)))
	if len(r.Services) != 1 {
		t.Error("rook/ceph should be detected")
	}
}

func TestDashboardPort(t *testing.T) {
	r := Analyze(col(svc("ceph1", "ceph/ceph", nil, []compose.PortMapping{allPort(8443)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected dashboard port finding")
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("ceph1", "ceph/ceph", []string{"CEPH_AUTH=none"}, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "Ceph Security Audit") {
		t.Error("expected header")
	}
	if !strings.Contains(text, "/test") {
		t.Error("expected path in output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No Ceph services found") {
		t.Error("expected empty message")
	}
}

func TestReportPath(t *testing.T) {
	r := Analyze(colPath("/mydir"))
	if r.Path != "/mydir" {
		t.Errorf("expected /mydir, got %s", r.Path)
	}
}
