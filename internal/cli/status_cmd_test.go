package cli

import (
	"strings"
	"testing"
)

func TestBuildStatusEmpty(t *testing.T) {
	result := buildStatus(nil)
	if result.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", result.TotalFindings)
	}
	if result.Grade != "A" {
		t.Errorf("expected grade A, got %s", result.Grade)
	}
	if result.PassRate != 100.0 {
		t.Errorf("expected 100%% pass rate, got %.1f", result.PassRate)
	}
}

func TestBuildStatusWithFindings(t *testing.T) {
	findings := []statusFinding{
		{RuleID: "net_open_port", Severity: "high", File: "docker-compose.yml"},
		{RuleID: "net_open_port", Severity: "high", File: "stack.yml"},
		{RuleID: "auth_missing", Severity: "critical", File: "config.yml"},
		{RuleID: "env_secret", Severity: "medium", File: ".env"},
	}
	result := buildStatus(findings)
	if result.TotalFindings != 4 {
		t.Errorf("expected 4 findings, got %d", result.TotalFindings)
	}
	if result.Grade != "F" {
		t.Errorf("expected grade F (critical present), got %s", result.Grade)
	}
	if result.BySeverity["critical"] != 1 {
		t.Errorf("expected 1 critical, got %d", result.BySeverity["critical"])
	}
	if result.BySeverity["high"] != 2 {
		t.Errorf("expected 2 high, got %d", result.BySeverity["high"])
	}
}

func TestBuildStatusGrade(t *testing.T) {
	tests := []struct {
		sevs  map[string]int
		grade string
	}{
		{map[string]int{}, "A"},
		{map[string]int{"medium": 3}, "A"},
		{map[string]int{"medium": 10}, "B"},
		{map[string]int{"high": 2}, "C"},
		{map[string]int{"high": 10}, "D"},
		{map[string]int{"critical": 1}, "F"},
	}
	for _, tt := range tests {
		got := computeGrade(tt.sevs)
		if got != tt.grade {
			t.Errorf("computeGrade(%v) = %s, want %s", tt.sevs, got, tt.grade)
		}
	}
}

func TestFormatStatusText(t *testing.T) {
	result := statusResult{
		TotalFindings: 5,
		BySeverity:    map[string]int{"high": 2, "medium": 3},
		ByCategory:    map[string]int{"net": 2, "auth": 3},
		Grade:         "C",
		PassRate:      60.0,
		TopIssues: []statusIssue{
			{RuleID: "auth_missing", Count: 3, Severity: "high"},
		},
	}
	text := formatStatusText(result)
	if !strings.Contains(text, "Grade: C") {
		t.Errorf("missing grade: %s", text)
	}
	if !strings.Contains(text, "60.0%") {
		t.Errorf("missing pass rate: %s", text)
	}
	if !strings.Contains(text, "auth_missing") {
		t.Errorf("missing top issue: %s", text)
	}
}

func TestCategoryFromRule(t *testing.T) {
	got := categoryFromRule("net_open_port")
	if got != "net" {
		t.Errorf("expected net, got %s", got)
	}
	got2 := categoryFromRule("standalone")
	if got2 != "standalone" {
		t.Errorf("expected standalone, got %s", got2)
	}
}
