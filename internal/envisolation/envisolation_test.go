package envisolation

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
	if r.Summary.AvgIsolation != 0 {
		t.Fatalf("expected 0 avg, got %d", r.Summary.AvgIsolation)
	}
}

func TestNoEnvVars(t *testing.T) {
	svcs := []compose.Service{{Name: "web"}, {Name: "db"}}
	r := Analyze(collected(svcs))
	if r.Summary.WithEnvVars != 0 {
		t.Fatalf("expected 0 with env vars, got %d", r.Summary.WithEnvVars)
	}
	if r.Summary.AvgIsolation != 100 {
		t.Fatalf("expected 100 avg isolation for no env vars, got %d", r.Summary.AvgIsolation)
	}
}

func TestIsolatedEnvVars(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Environment: []string{"PORT=8080"}},
		{Name: "db", Environment: []string{"PGDATA=/var/lib/postgresql"}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for isolated vars, got %d", r.Summary.TotalFindings)
	}
}

func TestSharedEnvVar(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Environment: []string{"DB_HOST=postgres", "PORT=8080"}},
		{Name: "worker", Environment: []string{"DB_HOST=postgres"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "env_shared_var" && strings.Contains(f.Detail, "DB_HOST") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected env_shared_var finding for DB_HOST")
	}
}

func TestSensitiveExposed(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Environment: []string{"DB_PASSWORD=hunter2"}},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "env_sensitive_exposed" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected env_sensitive_exposed finding")
	}
}

func TestSharedSensitiveIsHigh(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Environment: []string{"API_KEY=abc123"}},
		{Name: "worker", Environment: []string{"API_KEY=abc123"}},
	}
	r := Analyze(collected(svcs))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "env_shared_var" && strings.Contains(f.Detail, "API_KEY") {
				if f.Severity != "high" {
					t.Fatalf("expected high severity for shared API_KEY, got %s", f.Severity)
				}
			}
		}
	}
}

func TestIsolationScorePenalty(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Environment: []string{"DB_HOST=pg", "REDIS_HOST=redis", "SECRET_KEY=abc"}},
		{Name: "worker", Environment: []string{"DB_HOST=pg", "REDIS_HOST=redis"}},
	}
	r := Analyze(collected(svcs))
	for _, sr := range r.Services {
		if sr.Name == "web" && sr.IsolationScore >= 100 {
			t.Fatalf("expected reduced isolation score for web, got %d", sr.IsolationScore)
		}
	}
}

func TestNoSensitiveForNormalVars(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Environment: []string{"PORT=8080", "LOG_LEVEL=debug"}},
	}
	r := Analyze(collected(svcs))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "env_sensitive_exposed" {
				t.Fatal("normal vars should not be flagged as sensitive")
			}
		}
	}
}

func TestFormatText(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Environment: []string{"PASSWORD=secret"}},
	}
	r := Analyze(collected(svcs))
	text := FormatText(r)
	if !strings.Contains(text, "Environment Variable") {
		t.Fatal("expected header in text output")
	}
	if !strings.Contains(text, "web") {
		t.Fatal("expected service name in output")
	}
}

func TestMultipleSensitiveVars(t *testing.T) {
	svcs := []compose.Service{
		{Name: "app", Environment: []string{"DB_PASSWORD=x", "API_TOKEN=y", "SECRET_KEY=z"}},
	}
	r := Analyze(collected(svcs))
	count := 0
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "env_sensitive_exposed" {
				count++
			}
		}
	}
	if count != 3 {
		t.Fatalf("expected 3 sensitive findings, got %d", count)
	}
}

func TestPerfectIsolationScore(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Environment: []string{"PORT=8080"}},
	}
	r := Analyze(collected(svcs))
	for _, sr := range r.Services {
		if sr.Name == "web" && sr.IsolationScore != 100 {
			t.Fatalf("expected 100 isolation for unique non-sensitive var, got %d", sr.IsolationScore)
		}
	}
}
