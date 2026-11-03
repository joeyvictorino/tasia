package cli

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestBuildComplianceResultEmpty(t *testing.T) {
	r := buildComplianceResult("/tmp", nil, "all")
	if r.Total != 0 {
		t.Errorf("total = %d, want 0", r.Total)
	}
	if len(r.Frameworks) != 0 {
		t.Errorf("frameworks = %d, want 0", len(r.Frameworks))
	}
}

func TestBuildComplianceResultMappedRule(t *testing.T) {
	findings := []rules.Finding{
		{ID: "privileged_container", Severity: rules.SeverityCritical, Title: "test"},
		{ID: "privileged_container", Severity: rules.SeverityCritical, Title: "test2"},
	}
	r := buildComplianceResult("/tmp", findings, "all")
	if r.Total != 2 {
		t.Errorf("total = %d, want 2", r.Total)
	}
	if len(r.Frameworks) == 0 {
		t.Fatal("expected at least one framework")
	}
	if r.Unmapped != 0 {
		t.Errorf("unmapped = %d, want 0", r.Unmapped)
	}
}

func TestBuildComplianceResultUnmapped(t *testing.T) {
	findings := []rules.Finding{
		{ID: "nonexistent_rule", Severity: rules.SeverityLow, Title: "test"},
	}
	r := buildComplianceResult("/tmp", findings, "all")
	if r.Unmapped != 1 {
		t.Errorf("unmapped = %d, want 1", r.Unmapped)
	}
}

func TestBuildComplianceResultFrameworkFilter(t *testing.T) {
	findings := []rules.Finding{
		{ID: "privileged_container", Severity: rules.SeverityCritical, Title: "test"},
	}
	r := buildComplianceResult("/tmp", findings, "SOC2")
	for _, fw := range r.Frameworks {
		if fw.Framework != "SOC2" {
			t.Errorf("expected only SOC2 framework, got %s", fw.Framework)
		}
	}
}

func TestRunComplianceNoArgs(t *testing.T) {
	err := runCompliance([]string{"--path", t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRunComplianceJSON(t *testing.T) {
	err := runCompliance([]string{"--path", t.TempDir(), "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
}
