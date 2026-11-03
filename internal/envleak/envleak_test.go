package envleak

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Services: services},
		},
	}
}

func svc(name string, env []string, netMode string, pidMode string) compose.Service {
	return compose.Service{
		Name:        name,
		Environment: env,
		NetworkMode: netMode,
		PidMode:     pidMode,
	}
}

func TestAnalyze_Empty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalLeakPaths != 0 {
		t.Fatalf("expected 0 leak paths, got %d", r.Summary.TotalLeakPaths)
	}
}

func TestAnalyze_NoSharing(t *testing.T) {
	c := makeCollected(
		svc("web", []string{"PORT=8080"}, "", ""),
		svc("db", []string{"POSTGRES_PASSWORD=secret"}, "", ""),
	)
	r := Analyze(c)
	if r.Summary.TotalLeakPaths != 0 {
		t.Fatalf("expected 0 leak paths, got %d", r.Summary.TotalLeakPaths)
	}
}

func TestAnalyze_SharedNetworkNoSecrets(t *testing.T) {
	c := makeCollected(
		svc("app", []string{"PORT=3000"}, "", ""),
		svc("sidecar", nil, "service:app", ""),
	)
	r := Analyze(c)
	if r.Summary.TotalLeakPaths != 1 {
		t.Fatalf("expected 1 leak path, got %d", r.Summary.TotalLeakPaths)
	}
	if r.Paths[0].Severity != "medium" {
		t.Fatalf("expected medium severity, got %s", r.Paths[0].Severity)
	}
	if r.Paths[0].Mechanism != "shared_network_namespace" {
		t.Fatalf("expected shared_network_namespace, got %s", r.Paths[0].Mechanism)
	}
}

func TestAnalyze_SharedNetworkWithSecrets(t *testing.T) {
	c := makeCollected(
		svc("db", []string{"DB_PASSWORD=hunter2", "DB_HOST=localhost"}, "", ""),
		svc("proxy", nil, "service:db", ""),
	)
	r := Analyze(c)
	if r.Summary.TotalLeakPaths != 1 {
		t.Fatalf("expected 1 leak path, got %d", r.Summary.TotalLeakPaths)
	}
	if r.Paths[0].Severity != "high" {
		t.Fatalf("expected high severity, got %s", r.Paths[0].Severity)
	}
	if len(r.Paths[0].EnvVars) != 1 || r.Paths[0].EnvVars[0] != "DB_PASSWORD" {
		t.Fatalf("expected [DB_PASSWORD], got %v", r.Paths[0].EnvVars)
	}
}

func TestAnalyze_SharedPidNoSecrets(t *testing.T) {
	c := makeCollected(
		svc("worker", []string{"CONCURRENCY=4"}, "", ""),
		svc("debugger", nil, "", "service:worker"),
	)
	r := Analyze(c)
	if r.Summary.TotalLeakPaths != 1 {
		t.Fatalf("expected 1 leak path, got %d", r.Summary.TotalLeakPaths)
	}
	if r.Paths[0].Severity != "high" {
		t.Fatalf("expected high severity, got %s", r.Paths[0].Severity)
	}
	if r.Paths[0].Mechanism != "shared_pid_namespace" {
		t.Fatalf("expected shared_pid_namespace, got %s", r.Paths[0].Mechanism)
	}
}

func TestAnalyze_SharedPidWithSecrets(t *testing.T) {
	c := makeCollected(
		svc("api", []string{"API_TOKEN=abc123", "SECRET_KEY=xyz"}, "", ""),
		svc("monitor", nil, "", "service:api"),
	)
	r := Analyze(c)
	if r.Summary.TotalLeakPaths != 1 {
		t.Fatalf("expected 1 leak path, got %d", r.Summary.TotalLeakPaths)
	}
	if r.Paths[0].Severity != "critical" {
		t.Fatalf("expected critical severity, got %s", r.Paths[0].Severity)
	}
	if len(r.Paths[0].EnvVars) != 2 {
		t.Fatalf("expected 2 sensitive vars, got %d", len(r.Paths[0].EnvVars))
	}
}

func TestAnalyze_BothModes(t *testing.T) {
	c := makeCollected(
		svc("target", []string{"PASSWORD=secret"}, "", ""),
		svc("attacker", nil, "service:target", "service:target"),
	)
	r := Analyze(c)
	if r.Summary.TotalLeakPaths != 2 {
		t.Fatalf("expected 2 leak paths, got %d", r.Summary.TotalLeakPaths)
	}
	if r.Summary.HighRiskCount != 2 {
		t.Fatalf("expected 2 high risk, got %d", r.Summary.HighRiskCount)
	}
}

func TestAnalyze_UnknownTarget(t *testing.T) {
	c := makeCollected(
		svc("sidecar", nil, "service:nonexistent", ""),
	)
	r := Analyze(c)
	if r.Summary.TotalLeakPaths != 0 {
		t.Fatalf("expected 0 leak paths for unknown target, got %d", r.Summary.TotalLeakPaths)
	}
}

func TestAnalyze_MultipleServices(t *testing.T) {
	c := makeCollected(
		svc("db", []string{"DB_PASSWORD=secret"}, "", ""),
		svc("cache", []string{"REDIS_AUTH=pass"}, "", ""),
		svc("proxy", nil, "service:db", ""),
		svc("debug", nil, "", "service:cache"),
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 4 {
		t.Fatalf("expected 4 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalLeakPaths != 2 {
		t.Fatalf("expected 2 leak paths, got %d", r.Summary.TotalLeakPaths)
	}
}

func TestFindSensitiveVars(t *testing.T) {
	vars := []string{
		"DB_PASSWORD=hunter2",
		"PORT=8080",
		"API_KEY=abc",
		"DEBUG=true",
		"JWT_SECRET=xyz",
	}
	got := findSensitiveVars(vars)
	if len(got) != 3 {
		t.Fatalf("expected 3 sensitive vars, got %d: %v", len(got), got)
	}
}

func TestFormatText(t *testing.T) {
	c := makeCollected(
		svc("db", []string{"PASSWORD=x"}, "", ""),
		svc("sidecar", nil, "service:db", ""),
	)
	r := Analyze(c)
	out := FormatText(r)
	if !strings.Contains(out, "Environment Variable Leak") {
		t.Fatal("expected header in text output")
	}
	if !strings.Contains(out, "shared_network_namespace") {
		t.Fatal("expected mechanism in text output")
	}
}

func TestFormatJSON(t *testing.T) {
	c := makeCollected(
		svc("db", []string{"TOKEN=x"}, "", ""),
		svc("proxy", nil, "", "service:db"),
	)
	r := Analyze(c)
	out := FormatJSON(r)
	if !strings.Contains(out, `"total_leak_paths"`) {
		t.Fatal("expected total_leak_paths in JSON")
	}
}
