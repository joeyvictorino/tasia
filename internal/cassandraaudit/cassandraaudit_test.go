package cassandraaudit

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

func TestIsCassandraImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"cassandra:4.1", true},
		{"bitnami/cassandra:latest", true},
		{"datastax/dse-server:6.8", true},
		{"scylladb/scylla:5.2", true},
		{"nginx:latest", false},
	}
	for _, tt := range tests {
		if got := isCassandraImage(tt.image); got != tt.want {
			t.Errorf("isCassandraImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoAuth(t *testing.T) {
	r := Analyze(col(svc("db", "cassandra:4", []string{"CASSANDRA_AUTHENTICATOR=AllowAllAuthenticator"}, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected cassandra_no_auth finding")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("db", "cassandra:4", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected cassandra_no_tls finding")
	}
}

func TestNoInternodeEncryption(t *testing.T) {
	r := Analyze(col(svc("db", "cassandra:4", nil, nil)))
	if r.Summary.NoEncryption == 0 {
		t.Error("expected cassandra_no_internode_encryption finding")
	}
}

func TestExposedPort(t *testing.T) {
	r := Analyze(col(svc("db", "cassandra:4", nil, []compose.PortMapping{allIf(9042)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected cassandra_exposed_port finding")
	}
}

func TestJMXPort(t *testing.T) {
	r := Analyze(col(svc("db", "cassandra:4", nil, []compose.PortMapping{allIf(7199)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected JMX port finding")
	}
}

func TestDefaultPassword(t *testing.T) {
	r := Analyze(col(svc("db", "cassandra:4", []string{"CASSANDRA_PASSWORD=cassandra"}, nil)))
	if r.Summary.DefaultPassword == 0 {
		t.Error("expected cassandra_default_password finding")
	}
}

func TestJMXNoAuth(t *testing.T) {
	r := Analyze(col(svc("db", "cassandra:4", []string{"jmx_remote_authenticate=false"}, nil)))
	if r.Summary.JMXEnabled == 0 {
		t.Error("expected cassandra_jmx_exposed finding")
	}
}

func TestCleanService(t *testing.T) {
	r := Analyze(col(svc("db", "cassandra:4", []string{
		"CASSANDRA_AUTHENTICATOR=PasswordAuthenticator",
		"CLIENT_ENCRYPTION_ENABLED=TRUE",
		"INTERNODE_ENCRYPTION=ALL",
	}, nil)))
	total := r.Summary.NoAuth + r.Summary.NoTLS + r.Summary.NoEncryption
	if total != 0 {
		t.Errorf("expected 0 auth/tls/encryption findings, got %d", total)
	}
}

func TestNonCassandraSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestMultiplePorts(t *testing.T) {
	r := Analyze(col(svc("db", "cassandra:4", nil, []compose.PortMapping{allIf(9042), allIf(9160), allIf(7199)})))
	if r.Summary.ExposedPort != 3 {
		t.Errorf("expected 3 port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("db", "cassandra:4", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "Cassandra Security Audit") {
		t.Error("missing title")
	}
}

func TestEmptyCollection(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	if len(r.Services) != 0 {
		t.Error("expected empty report")
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(col(
		svc("db1", "cassandra:4", nil, nil),
		svc("db2", "bitnami/cassandra", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}

func TestScyllaDB(t *testing.T) {
	r := Analyze(col(svc("scylla", "scylladb/scylla:5.2", nil, nil)))
	if len(r.Services) != 1 {
		t.Fatal("ScyllaDB should be detected")
	}
}

func TestThriftPort(t *testing.T) {
	r := Analyze(col(svc("db", "cassandra:4", nil, []compose.PortMapping{allIf(9160)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected Thrift port finding")
	}
}

func TestReportPath(t *testing.T) {
	r := Analyze(colPath("/mydir"))
	if r.Path != "/mydir" {
		t.Errorf("expected /mydir, got %s", r.Path)
	}
}
