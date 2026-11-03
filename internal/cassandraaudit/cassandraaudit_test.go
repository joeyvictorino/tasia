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

func localPort(target int) compose.PortMapping {
	return compose.PortMapping{HostPort: target, TargetPort: target, HostIP: "127.0.0.1"}
}

func col(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func TestIsCassandraImage(t *testing.T) {
	if !isCassandraImage("cassandra:4.1") {
		t.Error("should detect cassandra")
	}
	if !isCassandraImage("bitnami/cassandra:latest") {
		t.Error("should detect bitnami/cassandra")
	}
	if isCassandraImage("postgres:15") {
		t.Error("should not detect postgres")
	}
}

func TestNoAuth(t *testing.T) {
	s := svc("db", "cassandra:4.1", nil, nil)
	r := Analyze(col(s))
	if r.Summary.NoAuth != 1 {
		t.Errorf("expected NoAuth=1, got %d", r.Summary.NoAuth)
	}
}

func TestAuthDisabledExplicitly(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_AUTHENTICATOR=AllowAllAuthenticator"}, nil)
	r := Analyze(col(s))
	if r.Summary.NoAuth != 1 {
		t.Errorf("expected NoAuth=1, got %d", r.Summary.NoAuth)
	}
}

func TestAuthEnabled(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_AUTHENTICATOR=PasswordAuthenticator"}, nil)
	r := Analyze(col(s))
	if r.Summary.NoAuth != 0 {
		t.Errorf("expected NoAuth=0, got %d", r.Summary.NoAuth)
	}
}

func TestAuthWithPassword(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_PASSWORD=strongpw123"}, nil)
	r := Analyze(col(s))
	if r.Summary.NoAuth != 0 {
		t.Errorf("expected NoAuth=0, got %d", r.Summary.NoAuth)
	}
}

func TestNoTLS(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_PASSWORD=secret"}, nil)
	r := Analyze(col(s))
	if r.Summary.NoTLS != 1 {
		t.Errorf("expected NoTLS=1, got %d", r.Summary.NoTLS)
	}
}

func TestTLSEnabled(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_PASSWORD=secret", "CASSANDRA_CLIENT_ENCRYPTION=true"}, nil)
	r := Analyze(col(s))
	if r.Summary.NoTLS != 0 {
		t.Errorf("expected NoTLS=0, got %d", r.Summary.NoTLS)
	}
}

func TestExposedCQLPort(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_PASSWORD=secret"}, []compose.PortMapping{allIf(9042)})
	r := Analyze(col(s))
	if r.Summary.ExposedPort != 1 {
		t.Errorf("expected ExposedPort=1, got %d", r.Summary.ExposedPort)
	}
}

func TestExposedJMXPort(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_PASSWORD=secret"}, []compose.PortMapping{allIf(7199)})
	r := Analyze(col(s))
	if r.Summary.ExposedPort != 1 {
		t.Errorf("expected ExposedPort=1, got %d", r.Summary.ExposedPort)
	}
}

func TestExposedThriftPort(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_PASSWORD=secret"}, []compose.PortMapping{allIf(9160)})
	r := Analyze(col(s))
	if r.Summary.ExposedPort != 1 {
		t.Errorf("expected ExposedPort=1, got %d", r.Summary.ExposedPort)
	}
}

func TestLocalPortNotFlagged(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_PASSWORD=secret"}, []compose.PortMapping{localPort(9042)})
	r := Analyze(col(s))
	if r.Summary.ExposedPort != 0 {
		t.Errorf("expected ExposedPort=0, got %d", r.Summary.ExposedPort)
	}
}

func TestDefaultPassword(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_PASSWORD=cassandra"}, nil)
	r := Analyze(col(s))
	if r.Summary.DefaultPassword != 1 {
		t.Errorf("expected DefaultPassword=1, got %d", r.Summary.DefaultPassword)
	}
}

func TestStrongPassword(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_PASSWORD=xK9mP2wQ7nR4"}, nil)
	r := Analyze(col(s))
	if r.Summary.DefaultPassword != 0 {
		t.Errorf("expected DefaultPassword=0, got %d", r.Summary.DefaultPassword)
	}
}

func TestJMXExposed(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_PASSWORD=secret", "LOCAL_JMX=no"}, []compose.PortMapping{allIf(7199)})
	r := Analyze(col(s))
	if r.Summary.JMXExposed != 1 {
		t.Errorf("expected JMXExposed=1, got %d", r.Summary.JMXExposed)
	}
}

func TestJMXNotExposedLocal(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_PASSWORD=secret", "LOCAL_JMX=no"}, []compose.PortMapping{localPort(7199)})
	r := Analyze(col(s))
	if r.Summary.JMXExposed != 0 {
		t.Errorf("expected JMXExposed=0, got %d", r.Summary.JMXExposed)
	}
}

func TestNonCassandraIgnored(t *testing.T) {
	s := svc("pg", "postgres:15", nil, nil)
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

func TestMultipleExposedPorts(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{"CASSANDRA_PASSWORD=secret"}, []compose.PortMapping{allIf(9042), allIf(7199), allIf(9160)})
	r := Analyze(col(s))
	if r.Summary.ExposedPort != 3 {
		t.Errorf("expected ExposedPort=3, got %d", r.Summary.ExposedPort)
	}
}

func TestFormatTextOutput(t *testing.T) {
	s := svc("db", "cassandra:4.1", nil, nil)
	r := Analyze(col(s))
	text := FormatText(r)
	if !strings.Contains(text, "Cassandra Security Audit") {
		t.Error("expected header")
	}
	if !strings.Contains(text, "db") {
		t.Error("expected service name")
	}
}

func TestFormatTextNoServices(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No Cassandra services found") {
		t.Error("expected no services message")
	}
}

func TestFullySecure(t *testing.T) {
	s := svc("db", "cassandra:4.1", []string{
		"CASSANDRA_AUTHENTICATOR=PasswordAuthenticator",
		"CASSANDRA_PASSWORD=xK9mP2wQ7nR4",
		"CASSANDRA_CLIENT_ENCRYPTION=true",
	}, []compose.PortMapping{localPort(9042)})
	r := Analyze(col(s))
	total := r.Summary.NoAuth + r.Summary.NoTLS + r.Summary.ExposedPort + r.Summary.DefaultPassword + r.Summary.JMXExposed
	if total != 0 {
		t.Errorf("expected 0 findings for fully secure setup, got %d", total)
	}
}
