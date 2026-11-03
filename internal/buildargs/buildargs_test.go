package buildargs

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services []compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: services}},
	}
}

func TestEmptyServices(t *testing.T) {
	r := Analyze(collected(nil))
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0, got %d", r.Summary.TotalServices)
	}
}

func TestNoEnvVars(t *testing.T) {
	svcs := []compose.Service{{Name: "web"}}
	r := Analyze(collected(svcs))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestSafeEnvVars(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Environment: []string{"PORT=8080", "LOG_LEVEL=debug"}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for safe vars, got %d", r.Summary.TotalFindings)
	}
}

func TestHardcodedPassword(t *testing.T) {
	svcs := []compose.Service{
		{Name: "db", Environment: []string{"MYSQL_ROOT_PASSWORD=hunter2"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "buildargs_hardcoded_secret" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected buildargs_hardcoded_secret for hardcoded password")
	}
}

func TestVariableRefNotFlagged(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Environment: []string{"API_KEY=${API_KEY}"}},
	}
	r := Analyze(collected(svcs))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "buildargs_hardcoded_secret" {
				t.Fatal("variable references should not be flagged as hardcoded")
			}
		}
	}
}

func TestWeakDefault(t *testing.T) {
	svcs := []compose.Service{
		{Name: "db", Environment: []string{"DB_PASSWORD=password"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "buildargs_weak_default" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected buildargs_weak_default for weak password")
	}
}

func TestEmbeddedBase64Key(t *testing.T) {
	svcs := []compose.Service{
		{Name: "api", Environment: []string{"SIGNING_KEY=dGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgZW5jb2RlZCBrZXk="}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "buildargs_embedded_key" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected buildargs_embedded_key for base64 encoded key")
	}
}

func TestRuntimeLeak(t *testing.T) {
	svcs := []compose.Service{
		{Name: "app", Entrypoint: []string{"myapp", "--password=secret123"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "buildargs_runtime_leak" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected buildargs_runtime_leak for inline secret in entrypoint")
	}
}

func TestCommandRuntimeLeak(t *testing.T) {
	svcs := []compose.Service{
		{Name: "app", Command: []string{"sh", "-c", "myapp --token=abc123"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "buildargs_runtime_leak" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected buildargs_runtime_leak for inline secret in command")
	}
}

func TestNoRuntimeLeakForSafeCommands(t *testing.T) {
	svcs := []compose.Service{
		{Name: "app", Command: []string{"myapp", "--port", "8080"}},
	}
	r := Analyze(collected(svcs))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "buildargs_runtime_leak" {
				t.Fatal("safe commands should not trigger runtime leak")
			}
		}
	}
}

func TestFormatText(t *testing.T) {
	svcs := []compose.Service{
		{Name: "db", Environment: []string{"DB_PASSWORD=admin"}},
	}
	r := Analyze(collected(svcs))
	text := FormatText(r)
	if !strings.Contains(text, "Build Arguments") {
		t.Fatal("expected header in text output")
	}
	if !strings.Contains(text, "db") {
		t.Fatal("expected service name in output")
	}
}

func TestMultipleFindings(t *testing.T) {
	svcs := []compose.Service{
		{Name: "app", Environment: []string{
			"DB_PASSWORD=admin",
			"API_SECRET=changeme",
			"NORMAL_VAR=hello",
		}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.TotalFindings < 3 {
		t.Fatalf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestShortValueNotBase64(t *testing.T) {
	svcs := []compose.Service{
		{Name: "app", Environment: []string{"SOME_KEY=short"}},
	}
	r := Analyze(collected(svcs))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "buildargs_embedded_key" {
				t.Fatal("short values should not be flagged as embedded keys")
			}
		}
	}
}
