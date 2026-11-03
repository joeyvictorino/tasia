package consulaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name, image string, env []string, ports []compose.PortMapping, cmd []string) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports, Command: cmd}
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

func TestMissingACL(t *testing.T) {
	r := Analyze(col(svc("consul", "hashicorp/consul", nil, nil, nil)))
	if r.Summary.NoACL == 0 {
		t.Error("expected no_acl finding")
	}
}

func TestACLConfigured(t *testing.T) {
	r := Analyze(col(svc("consul", "consul", []string{"CONSUL_HTTP_TOKEN=secret123"}, nil, nil)))
	if r.Summary.NoACL != 0 {
		t.Error("should not flag when ACL token present")
	}
}

func TestACLViaArgs(t *testing.T) {
	r := Analyze(col(svc("consul", "consul", nil, nil, []string{"agent", "-acl-enabled"})))
	if r.Summary.NoACL != 0 {
		t.Error("should not flag when ACL enabled via args")
	}
}

func TestMissingTLS(t *testing.T) {
	r := Analyze(col(svc("consul", "consul", nil, nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected no_tls finding")
	}
}

func TestTLSConfigured(t *testing.T) {
	r := Analyze(col(svc("consul", "consul", []string{"CONSUL_CACERT=/certs/ca.pem"}, nil, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("should not flag when TLS configured")
	}
}

func TestMissingGossipEncryption(t *testing.T) {
	r := Analyze(col(svc("consul", "consul", nil, nil, nil)))
	if r.Summary.NoEncryptGossip == 0 {
		t.Error("expected no_gossip_encrypt finding")
	}
}

func TestGossipEncryptionConfigured(t *testing.T) {
	r := Analyze(col(svc("consul", "consul", []string{"CONSUL_ENCRYPT=abc123"}, nil, nil)))
	if r.Summary.NoEncryptGossip != 0 {
		t.Error("should not flag when gossip encryption set")
	}
}

func TestExposedPort(t *testing.T) {
	r := Analyze(col(svc("consul", "consul", nil, []compose.PortMapping{allPort(8500)}, nil)))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected exposed_port finding")
	}
}

func TestLocalhostPort(t *testing.T) {
	r := Analyze(col(svc("consul", "consul", nil, []compose.PortMapping{localPort(8500)}, nil)))
	if r.Summary.ExposedPort != 0 {
		t.Error("localhost port should not be flagged")
	}
}

func TestDefaultToken(t *testing.T) {
	r := Analyze(col(svc("consul", "consul", []string{"CONSUL_HTTP_TOKEN=anonymous"}, nil, nil)))
	if r.Summary.DefaultToken == 0 {
		t.Error("expected default_token finding")
	}
}

func TestDevMode(t *testing.T) {
	r := Analyze(col(svc("consul", "consul", nil, nil, []string{"agent", "-dev"})))
	if r.Summary.DevMode == 0 {
		t.Error("expected dev_mode finding")
	}
}

func TestNonConsulService(t *testing.T) {
	r := Analyze(col(svc("redis", "redis:7", nil, nil, nil)))
	if len(r.Services) != 0 {
		t.Error("non-consul service should be ignored")
	}
}

func TestSummaryAggregation(t *testing.T) {
	r := Analyze(col(svc("consul", "consul", nil, []compose.PortMapping{allPort(8500)}, nil)))
	total := r.Summary.NoACL + r.Summary.NoTLS + r.Summary.ExposedPort + r.Summary.NoEncryptGossip
	if total == 0 {
		t.Error("expected some findings in summary")
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("consul", "consul", nil, nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "Consul Security Audit") {
		t.Error("expected header")
	}
	if !strings.Contains(text, "/test") {
		t.Error("expected path in output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No Consul services found") {
		t.Error("expected empty message")
	}
}

func TestReportPath(t *testing.T) {
	r := Analyze(colPath("/mydir"))
	if r.Path != "/mydir" {
		t.Errorf("expected /mydir, got %s", r.Path)
	}
}

func TestIsConsulImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"consul", true},
		{"hashicorp/consul:1.16", true},
		{"bitnami/consul", true},
		{"consul-enterprise:latest", true},
		{"redis:7", false},
		{"nginx", false},
	}
	for _, tt := range tests {
		got := isConsulImage(tt.image)
		if got != tt.want {
			t.Errorf("isConsulImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(col(
		svc("consul1", "consul", nil, nil, nil),
		svc("consul2", "hashicorp/consul", nil, nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}
