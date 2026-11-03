package zookeeperaudit

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

func TestMissingAuth(t *testing.T) {
	r := Analyze(col(svc("zk", "zookeeper", nil, nil, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected no_auth finding")
	}
}

func TestAuthConfigured(t *testing.T) {
	r := Analyze(col(svc("zk", "zookeeper", []string{"ZOO_ENABLE_AUTH=yes"}, nil, nil)))
	if r.Summary.NoAuth != 0 {
		t.Error("should not flag when auth enabled")
	}
}

func TestAuthViaArgs(t *testing.T) {
	r := Analyze(col(svc("zk", "zookeeper", nil, nil, []string{"--authProvider=sasl"})))
	if r.Summary.NoAuth != 0 {
		t.Error("should not flag when auth set via args")
	}
}

func TestMissingTLS(t *testing.T) {
	r := Analyze(col(svc("zk", "zookeeper", nil, nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected no_tls finding")
	}
}

func TestTLSConfigured(t *testing.T) {
	r := Analyze(col(svc("zk", "zookeeper", []string{"ZOO_TLS_CLIENT_AUTH=need"}, nil, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("should not flag when TLS configured")
	}
}

func TestExposedPort(t *testing.T) {
	r := Analyze(col(svc("zk", "zookeeper", nil, []compose.PortMapping{allPort(2181)}, nil)))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected exposed_port finding")
	}
}

func TestLocalhostPort(t *testing.T) {
	r := Analyze(col(svc("zk", "zookeeper", nil, []compose.PortMapping{localPort(2181)}, nil)))
	if r.Summary.ExposedPort != 0 {
		t.Error("localhost port should not be flagged")
	}
}

func TestPeerPort(t *testing.T) {
	r := Analyze(col(svc("zk", "zookeeper", nil, []compose.PortMapping{allPort(2888)}, nil)))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected exposed peer port finding")
	}
}

func TestFourLetterCommands(t *testing.T) {
	r := Analyze(col(svc("zk", "zookeeper", []string{"ZOO_4LW_COMMANDS_WHITELIST=*"}, nil, nil)))
	if r.Summary.FourLetterCmd == 0 {
		t.Error("expected four_letter_cmd finding")
	}
}

func TestAdminServer(t *testing.T) {
	r := Analyze(col(svc("zk", "zookeeper", []string{"ZOO_ADMINSERVER_ENABLED=true"}, nil, nil)))
	if r.Summary.AdminServer == 0 {
		t.Error("expected admin_server finding")
	}
}

func TestNonZookeeperService(t *testing.T) {
	r := Analyze(col(svc("redis", "redis:7", nil, nil, nil)))
	if len(r.Services) != 0 {
		t.Error("non-zookeeper service should be ignored")
	}
}

func TestSummaryAggregation(t *testing.T) {
	r := Analyze(col(svc("zk", "zookeeper", nil, []compose.PortMapping{allPort(2181)}, nil)))
	total := r.Summary.NoAuth + r.Summary.NoTLS + r.Summary.ExposedPort
	if total == 0 {
		t.Error("expected findings")
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("zk", "zookeeper", nil, nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "ZooKeeper Security Audit") {
		t.Error("expected header")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No ZooKeeper services found") {
		t.Error("expected empty message")
	}
}

func TestReportPath(t *testing.T) {
	r := Analyze(colPath("/mydir"))
	if r.Path != "/mydir" {
		t.Errorf("expected /mydir, got %s", r.Path)
	}
}

func TestIsZookeeperImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"zookeeper", true},
		{"bitnami/zookeeper:3.8", true},
		{"confluentinc/cp-zookeeper", true},
		{"wurstmeister/zookeeper", true},
		{"redis:7", false},
	}
	for _, tt := range tests {
		got := isZookeeperImage(tt.image)
		if got != tt.want {
			t.Errorf("isZookeeperImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(col(
		svc("zk1", "zookeeper", nil, nil, nil),
		svc("zk2", "bitnami/zookeeper", nil, nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}

func TestSkipACLYes(t *testing.T) {
	r := Analyze(col(svc("zk", "zookeeper", []string{"ZOO_SKIP_ACL=YES"}, nil, nil)))
	if r.Summary.NoACL == 0 {
		t.Error("expected no_acl finding when skip_acl=yes")
	}
}
