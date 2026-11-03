package deporder

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestMissingDependency(t *testing.T) {
	cf := compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			{Name: "web", DependsOn: map[string]compose.DependsOnCondition{"db": {}}},
		},
	}
	fr := analyzeFile(cf)
	found := false
	for _, f := range fr.Findings {
		if f.Rule == "missing_dependency" {
			found = true
		}
	}
	if !found {
		t.Error("expected missing_dependency finding")
	}
}

func TestValidDependency(t *testing.T) {
	cf := compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			{Name: "db"},
			{Name: "web", DependsOn: map[string]compose.DependsOnCondition{"db": {}}},
		},
	}
	fr := analyzeFile(cf)
	for _, f := range fr.Findings {
		if f.Rule == "missing_dependency" {
			t.Errorf("unexpected missing_dependency: %s", f.Message)
		}
	}
}

func TestCycleDetection(t *testing.T) {
	cf := compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			{Name: "a", DependsOn: map[string]compose.DependsOnCondition{"b": {}}},
			{Name: "b", DependsOn: map[string]compose.DependsOnCondition{"a": {}}},
		},
	}
	fr := analyzeFile(cf)
	found := false
	for _, f := range fr.Findings {
		if f.Rule == "dependency_cycle" {
			found = true
		}
	}
	if !found {
		t.Error("expected dependency_cycle finding")
	}
}

func TestNoCycle(t *testing.T) {
	cf := compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			{Name: "a", DependsOn: map[string]compose.DependsOnCondition{"b": {}}},
			{Name: "b"},
		},
	}
	cycles := detectCycles(cf.Services)
	if len(cycles) != 0 {
		t.Errorf("expected no cycles, got %d", len(cycles))
	}
}

func TestNoDependsOn(t *testing.T) {
	cf := compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			{Name: "web"},
			{Name: "db"},
		},
	}
	fr := analyzeFile(cf)
	found := false
	for _, f := range fr.Findings {
		if f.Rule == "no_depends_on" {
			found = true
		}
	}
	if !found {
		t.Error("expected no_depends_on finding")
	}
}

func TestSingleServiceNoDependsOn(t *testing.T) {
	cf := compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			{Name: "solo"},
		},
	}
	fr := analyzeFile(cf)
	for _, f := range fr.Findings {
		if f.Rule == "no_depends_on" {
			t.Error("single service should not trigger no_depends_on")
		}
	}
}

func TestAnalyze(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", DependsOn: map[string]compose.DependsOnCondition{"db": {}}},
					{Name: "db"},
				},
			},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFiles != 1 {
		t.Errorf("expected 1 file, got %d", r.Summary.TotalFiles)
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestSummarize(t *testing.T) {
	files := []FileResult{
		{
			File: "f1",
			Findings: []Finding{
				{Rule: "dependency_cycle"},
				{Rule: "missing_dependency"},
				{Rule: "no_depends_on"},
			},
		},
	}
	s := summarize(files)
	if s.Cycles != 1 || s.MissingDeps != 1 || s.NoDependsOn != 1 || s.TotalFindings != 3 {
		t.Errorf("unexpected summary: %+v", s)
	}
}

func TestFormatText(t *testing.T) {
	r := Report{
		Path: "/test",
		Files: []FileResult{
			{File: "docker-compose.yml", Findings: []Finding{
				{Level: "warning", Rule: "dependency_cycle", Message: "cycle detected"},
			}},
		},
		Summary: Summary{TotalFiles: 1, TotalFindings: 1, Cycles: 1},
	}
	text := FormatText(r)
	if !strings.Contains(text, "Dependency Order") {
		t.Error("expected title")
	}
	if !strings.Contains(text, "cycle detected") {
		t.Error("expected finding message")
	}
}

func TestFormatJSON(t *testing.T) {
	r := Report{
		Path: "/test",
		Summary: Summary{TotalFiles: 1},
	}
	j, _ := json.Marshal(r)
	var parsed Report
	if err := json.Unmarshal(j, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.Summary.TotalFiles != 1 {
		t.Error("JSON round-trip failed")
	}
}

func TestThreeNodeCycle(t *testing.T) {
	services := []compose.Service{
		{Name: "a", DependsOn: map[string]compose.DependsOnCondition{"b": {}}},
		{Name: "b", DependsOn: map[string]compose.DependsOnCondition{"c": {}}},
		{Name: "c", DependsOn: map[string]compose.DependsOnCondition{"a": {}}},
	}
	cycles := detectCycles(services)
	if len(cycles) == 0 {
		t.Error("expected cycle in 3-node graph")
	}
}
