package consulaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name, image string, env []string, ports []compose.PortMapping, cmds []string) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports, Command: cmds}
}

func allIf(target int) compose.PortMapping {
	return compose.PortMapping{HostPort: target, TargetPort: target, HostIP: "0.0.0.0"}
}

func localPort(target int) compose.PortMapping {
	return compose.PortMapping{HostPort: target, TargetPort: target, HostIP: "127.0.0.1"}
}

func col(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func TestIsConsulImage(t *testing.T) {
	if !isConsulImage("consul:1.15") {
		t.Error("should detect consul")
	}
	if !isConsulImage("hashicorp/consul:latest") {
		t.Error("should detect hashicorp/consul")
	}
	if isConsulImage("postgres:15") {
		t.Error("should not detect postgres")
	}
}

func TestNoACL(t *testing.T) {
	s := svc("consul", "consul:1.15", nil, nil, nil)
	r := Analyze(col(s))
	if r.Summary.NoACL != 1 {
		t.Errorf("expected NoACL=1, got %d", r.Summary.NoACL)
	}
}

func TestDevModeNoACL(t *testing.T) {
	s := svc("consul", "consul:1.15", nil, nil, []string{"agent", "-dev"})
	r := Analyze(col(s))
	if r.Summary.NoACL != 1 {
		t.Errorf("expected NoACL=1 in dev mode, got %d", r.Summary.NoACL)
	}
}

func TestACLEnabled(t *testing.T) {
	s := svc("consul", "consul:1.15", []string{"CONSUL_ACL_ENABLED=true"}, nil, nil)
	r := Analyze(col(s))
	if r.Summary.NoACL != 0 {
		t.Errorf("expected NoACL=0, got %d", r.Summary.NoACL)
	}
}

func TestACLInLocalConfig(t *testing.T) {
	s := svc("consul", "consul:1.15", []string{`CONSUL_LOCAL_CONFIG={"acl":{"enabled":true}}`}, nil, nil)
	r := Analyze(col(s))
	if r.Summary.NoACL != 0 {
		t.Errorf("expected NoACL=0, got %d", r.Summary.NoACL)
	}
}

func TestNoTLS(t *testing.T) {
	s := svc("consul", "consul:1.15", []string{"CONSUL_ACL_ENABLED=true"}, nil, nil)
	r := Analyze(col(s))
	if r.Summary.NoTLS != 1 {
		t.Errorf("expected NoTLS=1, got %d", r.Summary.NoTLS)
	}
}

func TestTLSEnabled(t *testing.T) {
	s := svc("consul", "consul:1.15", []string{"CONSUL_ACL_ENABLED=true", "CONSUL_HTTP_SSL=TRUE"}, nil, nil)
	r := Analyze(col(s))
	if r.Summary.NoTLS != 0 {
		t.Errorf("expected NoTLS=0, got %d", r.Summary.NoTLS)
	}
}

func TestExposedHTTPPort(t *testing.T) {
	s := svc("consul", "consul:1.15", []string{"CONSUL_ACL_ENABLED=true"}, []compose.PortMapping{allIf(8500)}, nil)
	r := Analyze(col(s))
	if r.Summary.ExposedPort != 1 {
		t.Errorf("expected ExposedPort=1, got %d", r.Summary.ExposedPort)
	}
}

func TestExposedDNSPort(t *testing.T) {
	s := svc("consul", "consul:1.15", []string{"CONSUL_ACL_ENABLED=true"}, []compose.PortMapping{allIf(8600)}, nil)
	r := Analyze(col(s))
	if r.Summary.ExposedPort != 1 {
		t.Errorf("expected ExposedPort=1, got %d", r.Summary.ExposedPort)
	}
}

func TestExposedRPCPort(t *testing.T) {
	s := svc("consul", "consul:1.15", []string{"CONSUL_ACL_ENABLED=true"}, []compose.PortMapping{allIf(8300)}, nil)
	r := Analyze(col(s))
	if r.Summary.ExposedPort != 1 {
		t.Errorf("expected ExposedPort=1, got %d", r.Summary.ExposedPort)
	}
}

func TestLocalPortNotFlagged(t *testing.T) {
	s := svc("consul", "consul:1.15", []string{"CONSUL_ACL_ENABLED=true"}, []compose.PortMapping{localPort(8500)}, nil)
	r := Analyze(col(s))
	if r.Summary.ExposedPort != 0 {
		t.Errorf("expected ExposedPort=0, got %d", r.Summary.ExposedPort)
	}
}

func TestUIExposedNoACL(t *testing.T) {
	s := svc("consul", "consul:1.15", nil, []compose.PortMapping{allIf(8500)}, []string{"agent", "-ui"})
	r := Analyze(col(s))
	if r.Summary.UIExposed != 1 {
		t.Errorf("expected UIExposed=1, got %d", r.Summary.UIExposed)
	}
}

func TestUIExposedDevMode(t *testing.T) {
	s := svc("consul", "consul:1.15", nil, []compose.PortMapping{allIf(8500)}, []string{"agent", "-dev"})
	r := Analyze(col(s))
	if r.Summary.UIExposed != 1 {
		t.Errorf("expected UIExposed=1 in dev mode, got %d", r.Summary.UIExposed)
	}
}

func TestUINotExposedWithACL(t *testing.T) {
	s := svc("consul", "consul:1.15", []string{"CONSUL_ACL_ENABLED=true"}, []compose.PortMapping{allIf(8500)}, []string{"agent", "-ui"})
	r := Analyze(col(s))
	if r.Summary.UIExposed != 0 {
		t.Errorf("expected UIExposed=0 with ACL, got %d", r.Summary.UIExposed)
	}
}

func TestNoGossipEncryption(t *testing.T) {
	s := svc("consul", "consul:1.15", []string{"CONSUL_ACL_ENABLED=true"}, nil, nil)
	r := Analyze(col(s))
	if r.Summary.NoGossipEncrypt != 1 {
		t.Errorf("expected NoGossipEncrypt=1, got %d", r.Summary.NoGossipEncrypt)
	}
}

func TestGossipEncryptionEnabled(t *testing.T) {
	s := svc("consul", "consul:1.15", []string{"CONSUL_ACL_ENABLED=true", "CONSUL_ENCRYPT=abc123"}, nil, nil)
	r := Analyze(col(s))
	if r.Summary.NoGossipEncrypt != 0 {
		t.Errorf("expected NoGossipEncrypt=0, got %d", r.Summary.NoGossipEncrypt)
	}
}

func TestNonConsulIgnored(t *testing.T) {
	s := svc("pg", "postgres:15", nil, nil, nil)
	r := Analyze(col(s))
	if len(r.Services) != 0 {
		t.Error("expected no services")
	}
}

func TestNoServices(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	if len(r.Services) != 0 {
		t.Error("expected no services")
	}
}

func TestFormatTextOutput(t *testing.T) {
	s := svc("consul", "consul:1.15", nil, nil, nil)
	r := Analyze(col(s))
	text := FormatText(r)
	if !strings.Contains(text, "Consul Security Audit") {
		t.Error("expected header")
	}
}

func TestFormatTextNoServices(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No Consul services found") {
		t.Error("expected no services message")
	}
}

func TestMultipleExposedPorts(t *testing.T) {
	s := svc("consul", "consul:1.15", []string{"CONSUL_ACL_ENABLED=true"}, []compose.PortMapping{allIf(8500), allIf(8600), allIf(8300), allIf(8301), allIf(8302)}, nil)
	r := Analyze(col(s))
	if r.Summary.ExposedPort != 5 {
		t.Errorf("expected ExposedPort=5, got %d", r.Summary.ExposedPort)
	}
}

func TestFullySecure(t *testing.T) {
	s := svc("consul", "consul:1.15", []string{
		"CONSUL_ACL_ENABLED=true",
		"CONSUL_HTTP_SSL=TRUE",
		"CONSUL_ENCRYPT=secretkey",
	}, []compose.PortMapping{localPort(8500)}, []string{"agent", "-ui"})
	r := Analyze(col(s))
	total := r.Summary.NoACL + r.Summary.NoTLS + r.Summary.ExposedPort + r.Summary.UIExposed + r.Summary.NoGossipEncrypt
	if total != 0 {
		t.Errorf("expected 0 findings for fully secure setup, got %d", total)
	}
}
