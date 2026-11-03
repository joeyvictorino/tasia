package cli

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestBuildCoverageResultEmpty(t *testing.T) {
	r := buildCoverageResult("/tmp", nil)
	catalog := rules.Catalog()
	if r.TotalRules != len(catalog) {
		t.Errorf("total rules = %d, want %d", r.TotalRules, len(catalog))
	}
	if r.FiredCount != 0 {
		t.Errorf("fired = %d, want 0", r.FiredCount)
	}
	if r.CoveragePct != 0 {
		t.Errorf("coverage = %.1f, want 0", r.CoveragePct)
	}
	if r.NotFired != len(catalog) {
		t.Errorf("not fired = %d, want %d", r.NotFired, len(catalog))
	}
}

func TestBuildCoverageResultWithFindings(t *testing.T) {
	findings := []rules.Finding{
		{ID: "privileged_container", Severity: rules.SeverityCritical},
		{ID: "privileged_container", Severity: rules.SeverityCritical},
		{ID: "exposed_inference", Severity: rules.SeverityHigh},
	}
	r := buildCoverageResult("/tmp", findings)
	if r.FiredCount != 2 {
		t.Errorf("fired = %d, want 2", r.FiredCount)
	}
	if r.CoveragePct <= 0 {
		t.Error("coverage should be > 0 with findings")
	}

	found := false
	for _, e := range r.Rules {
		if e.RuleID == "privileged_container" {
			found = true
			if e.Count != 2 {
				t.Errorf("privileged_container count = %d, want 2", e.Count)
			}
			if !e.Fired {
				t.Error("privileged_container should show fired")
			}
		}
	}
	if !found {
		t.Error("privileged_container not found in rules")
	}
}

func TestBuildCoverageResultAllRulesPresent(t *testing.T) {
	r := buildCoverageResult("/tmp", nil)
	catalog := rules.Catalog()
	if len(r.Rules) != len(catalog) {
		t.Errorf("rules entries = %d, want %d", len(r.Rules), len(catalog))
	}
}

func TestRunCoverageNoArgs(t *testing.T) {
	err := runCoverage([]string{"--path", t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunCoverageJSON(t *testing.T) {
	err := runCoverage([]string{"--path", t.TempDir(), "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
}
