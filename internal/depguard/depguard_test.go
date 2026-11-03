package depguard

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	cf := compose.File{Path: "docker-compose.yml", Services: services}
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{cf}}
}

func findRule(results []ServiceResult, rule string) bool {
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return true
			}
		}
	}
	return false
}

func TestDepNoHealthcheck(t *testing.T) {
	c := mkCollected(
		compose.Service{
			Name:      "api",
			DependsOn: map[string]compose.DependsOnCondition{"db": {}},
		},
		compose.Service{Name: "db"},
	)
	r := Analyze(c)
	if !findRule(r.Services, "dep_no_healthcheck") {
		t.Error("expected dep_no_healthcheck when dependency has no healthcheck")
	}
}

func TestDepWithHealthcheck(t *testing.T) {
	c := mkCollected(
		compose.Service{
			Name:      "api",
			DependsOn: map[string]compose.DependsOnCondition{"db": {Condition: "service_healthy"}},
		},
		compose.Service{
			Name:        "db",
			Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "pg_isready"}},
		},
	)
	r := Analyze(c)
	if findRule(r.Services, "dep_no_healthcheck") {
		t.Error("should not flag dependency with healthcheck")
	}
}

func TestDepMissingCondition(t *testing.T) {
	c := mkCollected(
		compose.Service{
			Name:      "web",
			DependsOn: map[string]compose.DependsOnCondition{"redis": {}},
		},
		compose.Service{
			Name:        "redis",
			Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "redis-cli", "ping"}},
		},
	)
	r := Analyze(c)
	if !findRule(r.Services, "dep_missing_condition") {
		t.Error("expected dep_missing_condition when no condition specified")
	}
}

func TestDepWithCondition(t *testing.T) {
	c := mkCollected(
		compose.Service{
			Name:      "web",
			DependsOn: map[string]compose.DependsOnCondition{"redis": {Condition: "service_healthy"}},
		},
		compose.Service{
			Name:        "redis",
			Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "redis-cli", "ping"}},
		},
	)
	r := Analyze(c)
	if findRule(r.Services, "dep_missing_condition") {
		t.Error("should not flag dependency with explicit condition")
	}
}

func TestDepRestartMismatch(t *testing.T) {
	c := mkCollected(
		compose.Service{
			Name:      "worker",
			Restart:   "always",
			DependsOn: map[string]compose.DependsOnCondition{"queue": {Condition: "service_started"}},
		},
		compose.Service{
			Name:        "queue",
			Restart:     "no",
			Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "true"}},
		},
	)
	r := Analyze(c)
	if !findRule(r.Services, "dep_restart_mismatch") {
		t.Error("expected dep_restart_mismatch when dependent restarts always but dependency does not")
	}
}

func TestDepRestartMatch(t *testing.T) {
	c := mkCollected(
		compose.Service{
			Name:      "worker",
			Restart:   "always",
			DependsOn: map[string]compose.DependsOnCondition{"queue": {Condition: "service_started"}},
		},
		compose.Service{
			Name:        "queue",
			Restart:     "always",
			Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "true"}},
		},
	)
	r := Analyze(c)
	if findRule(r.Services, "dep_restart_mismatch") {
		t.Error("should not flag when both services restart always")
	}
}

func TestDepOrphan(t *testing.T) {
	c := mkCollected(
		compose.Service{
			Name:      "api",
			DependsOn: map[string]compose.DependsOnCondition{"missing-svc": {Condition: "service_started"}},
		},
	)
	r := Analyze(c)
	if !findRule(r.Services, "dep_orphan") {
		t.Error("expected dep_orphan for dependency on non-existent service")
	}
}

func TestDepCriticalChain(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "a", DependsOn: map[string]compose.DependsOnCondition{"b": {Condition: "service_started"}}},
		compose.Service{Name: "b", DependsOn: map[string]compose.DependsOnCondition{"c": {Condition: "service_started"}}, Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "true"}}},
		compose.Service{Name: "c", DependsOn: map[string]compose.DependsOnCondition{"d": {Condition: "service_started"}}, Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "true"}}},
		compose.Service{Name: "d", DependsOn: map[string]compose.DependsOnCondition{"e": {Condition: "service_started"}}, Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "true"}}},
		compose.Service{Name: "e", Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "true"}}},
	)
	r := Analyze(c)
	if !findRule(r.Services, "dep_critical_chain") {
		t.Error("expected dep_critical_chain for chain of depth 5")
	}
}

func TestDepShortChain(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "a", DependsOn: map[string]compose.DependsOnCondition{"b": {Condition: "service_started"}}},
		compose.Service{Name: "b", Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "true"}}},
	)
	r := Analyze(c)
	if findRule(r.Services, "dep_critical_chain") {
		t.Error("should not flag short dependency chain")
	}
}

func TestDepCircularRisk(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "x", DependsOn: map[string]compose.DependsOnCondition{"y": {Condition: "service_started"}}, Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "true"}}},
		compose.Service{Name: "y", DependsOn: map[string]compose.DependsOnCondition{"x": {Condition: "service_started"}}, Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "true"}}},
	)
	r := Analyze(c)
	if !findRule(r.Services, "dep_circular_risk") {
		t.Error("expected dep_circular_risk for circular dependency")
	}
}

func TestNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleServices(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "web"},
		compose.Service{Name: "api"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestSummaryTotals(t *testing.T) {
	c := mkCollected(
		compose.Service{
			Name:      "api",
			Restart:   "always",
			DependsOn: map[string]compose.DependsOnCondition{"db": {}},
		},
		compose.Service{Name: "db"},
	)
	r := Analyze(c)
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(
		compose.Service{
			Name:      "api",
			DependsOn: map[string]compose.DependsOnCondition{"db": {}},
		},
		compose.Service{Name: "db"},
	)
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Dependency Guard") {
		t.Error("expected 'Dependency Guard' in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "no findings") {
		t.Error("expected 'no findings' in output")
	}
}

func TestReportPath(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Path != "/test" {
		t.Errorf("expected path /test, got %s", r.Path)
	}
}

func TestUnlessStopped(t *testing.T) {
	c := mkCollected(
		compose.Service{
			Name:      "worker",
			Restart:   "unless-stopped",
			DependsOn: map[string]compose.DependsOnCondition{"queue": {Condition: "service_started"}},
		},
		compose.Service{
			Name:        "queue",
			Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "true"}},
		},
	)
	r := Analyze(c)
	if !findRule(r.Services, "dep_restart_mismatch") {
		t.Error("expected dep_restart_mismatch for unless-stopped with no-restart dependency")
	}
}
