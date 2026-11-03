package nomadaudit

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

func TestIsNomadImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"hashicorp/nomad:1.6", true},
		{"multani/nomad:latest", true},
		{"HASHICORP/NOMAD:1.7", true},
		{"nginx:latest", false},
		{"consul:1.15", false},
	}
	for _, tt := range tests {
		if got := isNomadImage(tt.image); got != tt.want {
			t.Errorf("isNomadImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoACL(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", nil, nil)))
	if r.Summary.NoACL == 0 {
		t.Error("expected nomad_no_acl finding when ACL not configured")
	}
}

func TestACLDisabled(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", []string{"NOMAD_ACL_ENABLED=false"}, nil)))
	if r.Summary.NoACL == 0 {
		t.Error("expected nomad_no_acl finding when ACL explicitly disabled")
	}
}

func TestACLEnabled(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", []string{"NOMAD_ACL_ENABLED=true"}, nil)))
	if r.Summary.NoACL != 0 {
		t.Error("should not flag ACL when enabled")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected nomad_no_tls finding")
	}
}

func TestTLSConfigured(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", []string{"NOMAD_TLS_CERT_FILE=/etc/nomad/cert.pem"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("should not flag TLS when configured")
	}
}

func TestExposedHTTPPort(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", nil, []compose.PortMapping{allIf(4646)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected nomad_exposed_port for HTTP API")
	}
}

func TestExposedRPCPort(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", nil, []compose.PortMapping{allIf(4647)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected nomad_exposed_port for RPC")
	}
}

func TestExposedSerfPort(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", nil, []compose.PortMapping{allIf(4648)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected nomad_exposed_port for Serf")
	}
}

func TestLocalhostPortNotFlagged(t *testing.T) {
	p := compose.PortMapping{HostPort: 4646, TargetPort: 4646, HostIP: "127.0.0.1"}
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", nil, []compose.PortMapping{p})))
	if r.Summary.ExposedPort != 0 {
		t.Error("localhost-bound port should not be flagged")
	}
}

func TestDefaultToken(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", []string{"NOMAD_TOKEN=secret"}, nil)))
	if r.Summary.DefaultToken == 0 {
		t.Error("expected nomad_default_token finding")
	}
}

func TestStrongToken(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", []string{"NOMAD_TOKEN=a7b9c4d8-e2f1-4a3b-8c5d-6e7f8a9b0c1d"}, nil)))
	if r.Summary.DefaultToken != 0 {
		t.Error("strong token should not be flagged")
	}
}

func TestRawExecEnabled(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", []string{"NOMAD_CLIENT_DRIVER_RAW_EXEC_ENABLED=true"}, nil)))
	if r.Summary.RawExecEnabled == 0 {
		t.Error("expected nomad_raw_exec finding")
	}
}

func TestRawExecDisabled(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", []string{"NOMAD_CLIENT_DRIVER_RAW_EXEC_ENABLED=false"}, nil)))
	if r.Summary.RawExecEnabled != 0 {
		t.Error("raw_exec disabled should not be flagged")
	}
}

func TestNonNomadSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestMultiplePorts(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", nil, []compose.PortMapping{allIf(4646), allIf(4647), allIf(4648)})))
	if r.Summary.ExposedPort != 3 {
		t.Errorf("expected 3 port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(col(
		svc("server", "hashicorp/nomad:1.6", nil, nil),
		svc("client", "hashicorp/nomad:1.6", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("nomad", "hashicorp/nomad:1.6", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "Nomad Security Audit") {
		t.Error("missing title")
	}
	if !strings.Contains(text, "/test") {
		t.Error("missing path")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	text := FormatText(Report{Path: "."})
	if !strings.Contains(text, "No Nomad services found") {
		t.Error("missing empty message")
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

func TestMultaniNomad(t *testing.T) {
	r := Analyze(col(svc("nomad", "multani/nomad:latest", nil, nil)))
	if len(r.Services) != 1 {
		t.Error("multani/nomad should be detected")
	}
}

func TestManagementToken(t *testing.T) {
	r := Analyze(col(svc("nomad", "hashicorp/nomad:1.6", []string{"NOMAD_MANAGEMENT_TOKEN=admin"}, nil)))
	if r.Summary.DefaultToken == 0 {
		t.Error("expected default token finding for management token")
	}
}
