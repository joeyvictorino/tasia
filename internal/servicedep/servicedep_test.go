package servicedep

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestNoDependencies(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "app"},
				{Name: "db"},
			},
		}},
	}
	r := Analyze(c)
	if r.Summary.TotalDependencies != 0 {
		t.Fatalf("expected 0 dependencies, got %d", r.Summary.TotalDependencies)
	}
}

func TestSimpleChain(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "web", DependsOn: map[string]compose.DependsOnCondition{"api": {}}},
				{Name: "api", DependsOn: map[string]compose.DependsOnCondition{"db": {}}},
				{Name: "db"},
			},
		}},
	}
	r := Analyze(c)
	if r.Summary.TotalDependencies != 2 {
		t.Fatalf("expected 2 dependencies, got %d", r.Summary.TotalDependencies)
	}
	if r.Summary.MaxDepth < 2 {
		t.Fatalf("expected max depth >= 2, got %d", r.Summary.MaxDepth)
	}
}

func TestCircularDependency(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "a", DependsOn: map[string]compose.DependsOnCondition{"b": {}}},
				{Name: "b", DependsOn: map[string]compose.DependsOnCondition{"a": {}}},
			},
		}},
	}
	r := Analyze(c)
	if r.Summary.CircularDeps == 0 {
		t.Fatal("expected circular dependency detected")
	}
	found := false
	for _, f := range r.Findings {
		if f.Category == "circular" && f.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected high severity circular finding")
	}
}

func TestCriticalNodeDetection(t *testing.T) {
	deps := map[string]compose.DependsOnCondition{"shared": {}}
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "shared"},
				{Name: "a", DependsOn: deps},
				{Name: "b", DependsOn: deps},
				{Name: "c", DependsOn: deps},
				{Name: "d", DependsOn: deps},
				{Name: "e", DependsOn: deps},
				{Name: "f", DependsOn: deps},
			},
		}},
	}
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Category == "critical-node" && f.Service == "shared" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected critical-node finding for shared service")
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Analyze(&collect.Collected{})
	out := FormatText(r)
	if !strings.Contains(out, "Service Dependency Analysis") {
		t.Fatal("expected header")
	}
}

func TestScoreGrade(t *testing.T) {
	tests := []struct {
		score int
		grade string
	}{
		{95, "A"}, {85, "B"}, {75, "C"}, {65, "D"}, {50, "F"},
	}
	for _, tt := range tests {
		got := scoreGrade(tt.score)
		if got != tt.grade {
			t.Errorf("scoreGrade(%d) = %s, want %s", tt.score, got, tt.grade)
		}
	}
}

func TestOrphanDetection(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "web", DependsOn: map[string]compose.DependsOnCondition{"db": {}}},
				{Name: "db"},
				{Name: "orphan"},
			},
		}},
	}
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Category == "orphan" && f.Service == "orphan" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected orphan finding")
	}
}
