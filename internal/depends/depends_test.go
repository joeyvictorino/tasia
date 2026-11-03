package depends

import (
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
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestNoDependencies(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web"},
		{Name: "db"},
	}
	r := Analyze(collected(svcs))
	if r.Summary.WithDependencies != 0 {
		t.Fatalf("expected 0 with deps, got %d", r.Summary.WithDependencies)
	}
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestSimpleDependency(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", DependsOn: map[string]compose.DependsOnCondition{
			"db": {},
		}},
		{Name: "db"},
	}
	r := Analyze(collected(svcs))
	if r.Summary.WithDependencies != 1 {
		t.Fatalf("expected 1 with deps, got %d", r.Summary.WithDependencies)
	}
}

func TestNoHealthcheckCondition(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", DependsOn: map[string]compose.DependsOnCondition{
			"db": {},
		}},
		{Name: "db"},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "depends_no_healthcheck" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected depends_no_healthcheck finding")
	}
}

func TestServiceStartedCondition(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", DependsOn: map[string]compose.DependsOnCondition{
			"db": {Condition: "service_started"},
		}},
		{Name: "db"},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "depends_no_healthcheck" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("service_started should still trigger depends_no_healthcheck")
	}
}

func TestHealthyConditionNoFinding(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", DependsOn: map[string]compose.DependsOnCondition{
			"db": {Condition: "service_healthy"},
		}},
		{Name: "db"},
	}
	r := Analyze(collected(svcs))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "depends_no_healthcheck" {
				t.Fatal("service_healthy should not trigger depends_no_healthcheck")
			}
		}
	}
}

func TestCircularDependency(t *testing.T) {
	svcs := []compose.Service{
		{Name: "a", DependsOn: map[string]compose.DependsOnCondition{
			"b": {Condition: "service_healthy"},
		}},
		{Name: "b", DependsOn: map[string]compose.DependsOnCondition{
			"a": {Condition: "service_healthy"},
		}},
	}
	r := Analyze(collected(svcs))
	if r.Summary.CircularDeps == 0 {
		t.Fatal("expected circular dependency to be detected")
	}
}

func TestLongChain(t *testing.T) {
	svcs := []compose.Service{
		{Name: "a", DependsOn: map[string]compose.DependsOnCondition{"b": {Condition: "service_healthy"}}},
		{Name: "b", DependsOn: map[string]compose.DependsOnCondition{"c": {Condition: "service_healthy"}}},
		{Name: "c", DependsOn: map[string]compose.DependsOnCondition{"d": {Condition: "service_healthy"}}},
		{Name: "d", DependsOn: map[string]compose.DependsOnCondition{"e": {Condition: "service_healthy"}}},
		{Name: "e", DependsOn: map[string]compose.DependsOnCondition{"f": {Condition: "service_healthy"}}},
		{Name: "f", DependsOn: map[string]compose.DependsOnCondition{"g": {Condition: "service_healthy"}}},
		{Name: "g"},
	}
	r := Analyze(collected(svcs))
	if r.Summary.LongChains == 0 {
		t.Fatal("expected long chain finding")
	}
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "depends_long_chain" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected depends_long_chain finding")
	}
}

func TestShortChainNoFinding(t *testing.T) {
	svcs := []compose.Service{
		{Name: "a", DependsOn: map[string]compose.DependsOnCondition{"b": {Condition: "service_healthy"}}},
		{Name: "b", DependsOn: map[string]compose.DependsOnCondition{"c": {Condition: "service_healthy"}}},
		{Name: "c"},
	}
	r := Analyze(collected(svcs))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "depends_long_chain" {
				t.Fatal("chain of 3 should not trigger long chain finding")
			}
		}
	}
}

func TestSinglePointOfFailure(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web1", DependsOn: map[string]compose.DependsOnCondition{"db": {Condition: "service_healthy"}}},
		{Name: "web2", DependsOn: map[string]compose.DependsOnCondition{"db": {Condition: "service_healthy"}}},
		{Name: "web3", DependsOn: map[string]compose.DependsOnCondition{"db": {Condition: "service_healthy"}}},
		{Name: "db"},
	}
	r := Analyze(collected(svcs))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "depends_single_point" && sr.Name == "db" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected single point of failure finding for db")
	}
}

func TestTwoDependentsNoSPOF(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web1", DependsOn: map[string]compose.DependsOnCondition{"db": {Condition: "service_healthy"}}},
		{Name: "web2", DependsOn: map[string]compose.DependsOnCondition{"db": {Condition: "service_healthy"}}},
		{Name: "db"},
	}
	r := Analyze(collected(svcs))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "depends_single_point" {
				t.Fatal("2 dependents should not trigger single point of failure")
			}
		}
	}
}

func TestMultipleDepsOnSameService(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", DependsOn: map[string]compose.DependsOnCondition{
			"db":    {Condition: "service_healthy"},
			"redis": {},
		}},
		{Name: "db"},
		{Name: "redis"},
	}
	r := Analyze(collected(svcs))
	// Should find depends_no_healthcheck for redis only
	count := 0
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "depends_no_healthcheck" {
				count++
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 depends_no_healthcheck finding, got %d", count)
	}
}

func TestFormatText(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", DependsOn: map[string]compose.DependsOnCondition{
			"db": {},
		}},
		{Name: "db"},
	}
	r := Analyze(collected(svcs))
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text output")
	}
	if !containsStr(text, "Service Dependency") {
		t.Fatal("expected header in text output")
	}
}

func TestServiceCompletedConditionNoFinding(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", DependsOn: map[string]compose.DependsOnCondition{
			"setup": {Condition: "service_completed_successfully"},
		}},
		{Name: "setup"},
	}
	r := Analyze(collected(svcs))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "depends_no_healthcheck" {
				t.Fatal("service_completed_successfully should not trigger depends_no_healthcheck")
			}
		}
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstr(s, substr))
}

func findSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
