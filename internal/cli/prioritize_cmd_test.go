package cli

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestBuildPrioritizedEmpty(t *testing.T) {
	r := buildPrioritized(nil, "/tmp", 20, 0)
	if r.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.TotalFindings)
	}
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 entries, got %d", len(r.Findings))
	}
}

func TestBuildPrioritizedOrdering(t *testing.T) {
	findings := []rules.Finding{
		{ID: "env_hardcoded_secret", Severity: "LOW", File: "/a/.env", Line: 1, Title: "Low sev"},
		{ID: "agent_runtime_privileged", Severity: "CRITICAL", File: "/a/compose.yml", Line: 5, Title: "Critical"},
		{ID: "compose_network_mode", Severity: "HIGH", File: "/a/compose.yml", Line: 10, Title: "High sev"},
	}
	r := buildPrioritized(findings, "/a", 20, 0)
	if r.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", r.TotalFindings)
	}
	if r.Findings[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL first, got %s", r.Findings[0].Severity)
	}
	if r.Findings[0].PriorityRank != 1 {
		t.Errorf("expected rank 1, got %d", r.Findings[0].PriorityRank)
	}
	if r.Findings[0].RiskScore <= r.Findings[len(r.Findings)-1].RiskScore {
		t.Error("first should have higher score than last")
	}
}

func TestBuildPrioritizedTopN(t *testing.T) {
	var findings []rules.Finding
	for i := 0; i < 30; i++ {
		findings = append(findings, rules.Finding{
			ID: "agent_x", Severity: "MEDIUM", File: "/a/f.yml", Line: i + 1,
		})
	}
	r := buildPrioritized(findings, "/a", 5, 0)
	if r.PrioritizedCount != 5 {
		t.Errorf("expected 5 prioritized, got %d", r.PrioritizedCount)
	}
}

func TestBuildPrioritizedMinScore(t *testing.T) {
	findings := []rules.Finding{
		{ID: "agent_runtime_privileged", Severity: "CRITICAL", File: "/a/f.yml", Line: 1},
		{ID: "env_x", Severity: "LOW", File: "/a/g.yml", Line: 1},
	}
	r := buildPrioritized(findings, "/a", 20, 50.0)
	for _, f := range r.Findings {
		if f.RiskScore < 50.0 {
			t.Errorf("finding %s has score %.1f below threshold", f.RuleID, f.RiskScore)
		}
	}
}

func TestBuildPrioritizedDensityBonus(t *testing.T) {
	findings := []rules.Finding{
		{ID: "agent_x", Severity: "HIGH", File: "/a/f.yml", Line: 1},
		{ID: "agent_y", Severity: "HIGH", File: "/a/f.yml", Line: 2},
		{ID: "agent_z", Severity: "HIGH", File: "/a/f.yml", Line: 3},
		{ID: "agent_w", Severity: "HIGH", File: "/a/f.yml", Line: 4},
	}
	r := buildPrioritized(findings, "/a", 20, 0)
	for _, f := range r.Findings {
		if !strings.Contains(f.Factors, "density") {
			t.Error("expected density factor for file with 4 findings")
		}
	}
}

func TestFormatPrioritizeText(t *testing.T) {
	r := prioritizeResult{
		TotalFindings:    3,
		PrioritizedCount: 2,
		Findings: []prioritizedFinding{
			{PriorityRank: 1, RuleID: "agent_x", Severity: "CRITICAL", File: "f.yml", Line: 5, RiskScore: 120.0, Factors: "sev=40, exp=3.0", Title: "Test"},
			{PriorityRank: 2, RuleID: "env_x", Severity: "HIGH", File: "g.yml", Line: 1, RiskScore: 62.5, Factors: "sev=25, exp=2.5"},
		},
	}
	text := formatPrioritizeText(r)
	if !strings.Contains(text, "Risk-Based Finding Prioritization") {
		t.Error("missing header")
	}
	if !strings.Contains(text, "#1") {
		t.Error("missing rank")
	}
	if !strings.Contains(text, "120.0") {
		t.Error("missing score")
	}
	if !strings.Contains(text, "Test") {
		t.Error("missing title")
	}
}
