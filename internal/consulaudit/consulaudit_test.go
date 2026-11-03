package consulaudit

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

func TestIsConsulImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"consul:1.16", true},
		{"hashicorp/consul:1.16", true},
		{"bitnami/consul:latest", true},
		{"Consul:latest", true},
		{"nginx:latest", false},
		{"postgres:15", false},
	}
	for _, tt := range tests {
		if got := isConsulImage(tt.image); got != tt.want {
			t.Errorf("isConsulImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoACL(t *testing.T) {
	r := Analyze(col(svc("consul", "consul:1.16", nil, nil)))
	if r.Summary.NoACL == 0 {
		t.Error("expected consul_no_acl finding")
	}
}

func TestACLEnabled(t *testing.T) {
	r := Analyze(col(svc("consul", "consul:1.16", []string{"CONSUL_ACL_ENABLED=TRUE"}, nil)))
	if r.Summary.NoACL != 0 {
		t.Error("expected no consul_no_acl when ACL enabled")
	}
}

func TestNoGossipEncryption(t *testing.T) {
	r := Analyze(col(svc("consul", "consul:1.16", nil, nil)))
	if r.Summary.NoGossipEncrypt == 0 {
		t.Error("expected consul_no_gossip_encrypt finding")
	}
}

func TestGossipEncryptionConfigured(t *testing.T) {
	r := Analyze(col(svc("consul", "consul:1.16", []string{"CONSUL_GOSSIP_ENCRYPTION_KEY=abc123"}, nil)))
	if r.Summary.NoGossipEncrypt != 0 {
		t.Error("expected no gossip encrypt finding when key set")
	}
}

func TestGossipViaCommand(t *testing.T) {
	r := Analyze(col(svcCmd("consul", "consul:1.16", nil, nil, []string{"agent", "-encrypt=xyz"})))
	if r.Summary.NoGossipEncrypt != 0 {
		t.Error("expected no gossip encrypt finding when -encrypt in command")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("consul", "consul:1.16", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected consul_no_tls finding")
	}
}

func TestTLSConfigured(t *testing.T) {
	r := Analyze(col(svc("consul", "consul:1.16", []string{"CONSUL_TLS_CERT=/cert.pem"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no TLS finding when CONSUL_TLS configured")
	}
}

func TestExposedPort(t *testing.T) {
	r := Analyze(col(svc("consul", "consul:1.16", nil, []compose.PortMapping{allIf(8500)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected consul_exposed_port finding")
	}
}

func TestDevModeCommand(t *testing.T) {
	r := Analyze(col(svcCmd("consul", "consul:1.16", nil, nil, []string{"agent", "-dev"})))
	if r.Summary.DevMode == 0 {
		t.Error("expected consul_dev_mode finding")
	}
}

func TestDevModeEnv(t *testing.T) {
	r := Analyze(col(svc("consul", "consul:1.16", []string{"CONSUL_DEV=true"}, nil)))
	if r.Summary.DevMode == 0 {
		t.Error("expected consul_dev_mode finding from env")
	}
}

func TestNonConsulSkipped(t *testing.T) {
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
	r := Analyze(col(svc("consul", "consul:1.16", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "Consul Security Audit") {
		t.Error("missing title")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No Consul services found") {
		t.Error("missing empty message")
	}
}

func TestMultiplePorts(t *testing.T) {
	r := Analyze(col(svc("consul", "consul:1.16", nil,
		[]compose.PortMapping{allIf(8500), allIf(8600), allIf(8300)})))
	if r.Summary.ExposedPort != 3 {
		t.Errorf("expected 3 port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestReportPath(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/mydir"})
	if r.Path != "/mydir" {
		t.Errorf("expected /mydir, got %s", r.Path)
	}
}

func TestCleanService(t *testing.T) {
	r := Analyze(col(svc("consul", "consul:1.16", []string{
		"CONSUL_ACL_ENABLED=TRUE",
		"CONSUL_GOSSIP_ENCRYPTION_KEY=secret",
		"CONSUL_TLS_CERT=/cert.pem",
	}, nil)))
	total := r.Summary.NoACL + r.Summary.NoGossipEncrypt + r.Summary.NoTLS
	if total != 0 {
		t.Errorf("expected 0 acl/gossip/tls findings, got %d", total)
	}
}
