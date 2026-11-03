package envtemplate

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name, image string, env []string, ports []compose.PortMapping) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports}
}

func col(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func TestCategorizesSecrets(t *testing.T) {
	r := Analyze(col(svc("db", "postgres:15", []string{
		"POSTGRES_PASSWORD=secret",
		"DB_API_KEY=abc123",
		"JWT_SECRET=xyz",
	}, nil)))
	if r.Summary.Secrets != 3 {
		t.Errorf("expected 3 secrets, got %d", r.Summary.Secrets)
	}
}

func TestCategorizesConfig(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", []string{
		"SERVER_PORT=8080",
		"HOST_NAME=localhost",
	}, nil)))
	if r.Summary.Config != 2 {
		t.Errorf("expected 2 config vars, got %d", r.Summary.Config)
	}
}

func TestCategorizesFeatureFlags(t *testing.T) {
	r := Analyze(col(svc("app", "myapp:1", []string{
		"FEATURE_ENABLE_X=true",
		"DEBUG_MODE=false",
	}, nil)))
	if r.Summary.FeatureFlags != 2 {
		t.Errorf("expected 2 feature flags, got %d", r.Summary.FeatureFlags)
	}
}

func TestDeduplicatesCrossService(t *testing.T) {
	r := Analyze(col(
		svc("web", "nginx", []string{"DATABASE_URL=pg://host/db"}, nil),
		svc("worker", "app", []string{"DATABASE_URL=pg://host/db"}, nil),
	))
	if r.Summary.Total != 1 {
		t.Errorf("expected 1 unique var, got %d", r.Summary.Total)
	}
	if len(r.Vars[0].Services) != 2 {
		t.Errorf("expected 2 services for shared var, got %d", len(r.Vars[0].Services))
	}
}

func TestEmptyCollection(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	if r.Summary.Total != 0 {
		t.Error("expected empty report")
	}
}

func TestFormatEnvExample(t *testing.T) {
	r := Analyze(col(svc("db", "postgres", []string{
		"POSTGRES_PASSWORD=secret",
		"MAX_CONNECTIONS=100",
	}, nil)))
	text := FormatEnvExample(r)
	if !strings.Contains(text, "POSTGRES_PASSWORD=") {
		t.Error("missing POSTGRES_PASSWORD in output")
	}
	if !strings.Contains(text, "secret/credential") {
		t.Error("missing secret annotation")
	}
	if !strings.Contains(text, "MAX_CONNECTIONS=") {
		t.Error("missing MAX_CONNECTIONS in output")
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(col(svc("db", "postgres", []string{"POSTGRES_PASSWORD=pw"}, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "Environment Template Report") {
		t.Error("missing title")
	}
}

func TestNoValueEnvVar(t *testing.T) {
	r := Analyze(col(svc("app", "myapp", []string{"SOME_VAR"}, nil)))
	if r.Summary.Total != 1 {
		t.Errorf("expected 1 var, got %d", r.Summary.Total)
	}
	if r.Vars[0].Value != "" {
		t.Errorf("expected empty value, got %q", r.Vars[0].Value)
	}
}

func TestSortedOutput(t *testing.T) {
	r := Analyze(col(svc("app", "myapp", []string{
		"ZEBRA=1",
		"ALPHA=2",
		"MIDDLE=3",
	}, nil)))
	if len(r.Vars) != 3 {
		t.Fatalf("expected 3 vars, got %d", len(r.Vars))
	}
	if r.Vars[0].Key != "ALPHA" || r.Vars[1].Key != "MIDDLE" || r.Vars[2].Key != "ZEBRA" {
		t.Errorf("expected sorted keys, got %s, %s, %s", r.Vars[0].Key, r.Vars[1].Key, r.Vars[2].Key)
	}
}
