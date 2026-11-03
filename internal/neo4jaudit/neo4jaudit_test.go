package neo4jaudit

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

func TestIsNeo4jImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"neo4j:5.9", true},
		{"bitnami/neo4j:latest", true},
		{"nginx:latest", false},
	}
	for _, tt := range tests {
		if got := isNeo4jImage(tt.image); got != tt.want {
			t.Errorf("isNeo4jImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoAuth(t *testing.T) {
	r := Analyze(col(svc("db", "neo4j:5", []string{"NEO4J_AUTH=none"}, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected neo4j_no_auth finding")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("db", "neo4j:5", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected neo4j_no_tls finding")
	}
}

func TestExposedPort(t *testing.T) {
	r := Analyze(col(svc("db", "neo4j:5", nil, []compose.PortMapping{allIf(7687)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected neo4j_exposed_port finding")
	}
}

func TestDefaultPassword(t *testing.T) {
	r := Analyze(col(svc("db", "neo4j:5", []string{"NEO4J_AUTH=neo4j/neo4j"}, nil)))
	if r.Summary.DefaultPassword == 0 {
		t.Error("expected neo4j_default_password finding")
	}
}

func TestRemoteShell(t *testing.T) {
	r := Analyze(col(svc("db", "neo4j:5", []string{"NEO4J_DBMS_SHELL_ENABLED=true"}, nil)))
	if r.Summary.RemoteShell == 0 {
		t.Error("expected neo4j_remote_shell finding")
	}
}

func TestBrowserExposed(t *testing.T) {
	r := Analyze(col(svc("db", "neo4j:5", []string{"NEO4J_AUTH=none"}, []compose.PortMapping{allIf(7474)})))
	if r.Summary.BrowserExposed == 0 {
		t.Error("expected neo4j_browser_exposed finding")
	}
}

func TestNonNeo4jSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(col(svc("db", "neo4j:5", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "Neo4j Security Audit") {
		t.Error("missing title")
	}
}

func TestEmptyCollection(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	if len(r.Services) != 0 {
		t.Error("expected empty report")
	}
}
