package riskmatrix

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestBuildMatrixEmpty(t *testing.T) {
	m := BuildMatrix(nil)
	if m.TotalRisk != 0 {
		t.Errorf("expected 0 total risk, got %.1f", m.TotalRisk)
	}
	if len(m.TopRisks) != 0 {
		t.Errorf("expected 0 top risks, got %d", len(m.TopRisks))
	}
	if len(m.Cells) != 20 {
		t.Errorf("expected 20 cells (4 sev × 5 like), got %d", len(m.Cells))
	}
}

func TestBuildMatrixSingleFinding(t *testing.T) {
	findings := []rules.Finding{
		{ID: "no_auth_chroma", Severity: rules.SeverityHigh, Title: "test"},
	}
	m := BuildMatrix(findings)
	if m.TotalRisk == 0 {
		t.Error("expected non-zero total risk")
	}
	if len(m.TopRisks) != 1 {
		t.Errorf("expected 1 top risk, got %d", len(m.TopRisks))
	}
}

func TestBuildMatrixMultipleFindings(t *testing.T) {
	findings := []rules.Finding{
		{ID: "no_auth_chroma", Severity: rules.SeverityHigh, Title: "a"},
		{ID: "no_auth_weaviate", Severity: rules.SeverityHigh, Title: "b"},
		{ID: "env_hardcoded_secret", Severity: rules.SeverityCritical, Title: "c"},
		{ID: "privileged_container", Severity: rules.SeverityMedium, Title: "d"},
	}
	m := BuildMatrix(findings)
	if m.TotalRisk == 0 {
		t.Error("expected non-zero total risk")
	}
	if len(m.TopRisks) == 0 {
		t.Error("expected top risks to be populated")
	}
}

func TestAssignLikelihood(t *testing.T) {
	cases := []struct {
		ruleID string
		want   string
	}{
		{"no_auth_chroma", "likely"},
		{"privileged_container", "possible"},
		{"env_hardcoded_secret", "likely"},
		{"agent_auto_approve", "likely"},
		{"unknown_rule", "possible"},
	}
	for _, tc := range cases {
		got := assignLikelihood(tc.ruleID)
		if got != tc.want {
			t.Errorf("assignLikelihood(%q) = %q, want %q", tc.ruleID, got, tc.want)
		}
	}
}

func TestRiskLookup(t *testing.T) {
	if riskLookup["CRITICAL"]["certain"] != "extreme" {
		t.Error("critical + certain should be extreme")
	}
	if riskLookup["LOW"]["rare"] != "low" {
		t.Error("low + rare should be low")
	}
	if riskLookup["MEDIUM"]["likely"] != "medium" {
		t.Error("medium + likely should be medium")
	}
}

func TestFormatText(t *testing.T) {
	findings := []rules.Finding{
		{ID: "no_auth_chroma", Severity: rules.SeverityHigh, Title: "test"},
	}
	m := BuildMatrix(findings)
	text := FormatText(m)
	if !strings.Contains(text, "Risk Matrix") {
		t.Error("expected 'Risk Matrix' header")
	}
	if !strings.Contains(text, "CRITICAL") {
		t.Error("expected severity labels")
	}
	if !strings.Contains(text, "Total Risk Score") {
		t.Error("expected total risk score")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	m := BuildMatrix(nil)
	text := FormatText(m)
	if !strings.Contains(text, "Total Risk Score: 0.0") {
		t.Error("expected zero total risk")
	}
}

func TestTopRisksCapped(t *testing.T) {
	var findings []rules.Finding
	for i := 0; i < 10; i++ {
		findings = append(findings, rules.Finding{
			ID:       "no_auth_chroma",
			Severity: rules.SeverityHigh,
			Title:    "test",
		})
	}
	findings = append(findings, rules.Finding{ID: "privileged_container", Severity: rules.SeverityCritical, Title: "a"})
	findings = append(findings, rules.Finding{ID: "env_hardcoded_secret", Severity: rules.SeverityCritical, Title: "b"})
	findings = append(findings, rules.Finding{ID: "restart_always_agent", Severity: rules.SeverityLow, Title: "c"})
	m := BuildMatrix(findings)
	if len(m.TopRisks) > 5 {
		t.Errorf("top risks should be capped at 5, got %d", len(m.TopRisks))
	}
}

func TestRuleIDsDedup(t *testing.T) {
	findings := []rules.Finding{
		{ID: "no_auth_chroma", Severity: rules.SeverityHigh, Title: "a"},
		{ID: "no_auth_chroma", Severity: rules.SeverityHigh, Title: "b"},
	}
	m := BuildMatrix(findings)
	for _, c := range m.Cells {
		if c.Count == 2 {
			if len(c.RuleIDs) != 1 {
				t.Errorf("expected deduplicated rule IDs, got %d", len(c.RuleIDs))
			}
		}
	}
}
