package cli

import (
	"strings"
	"testing"
)

func TestBenchRulesResultConstruction(t *testing.T) {
	result := benchRulesResult{
		Path:          "/tmp/test",
		Iterations:    3,
		CollectMs:     12.5,
		EvaluateMs:    8.3,
		TotalMs:       25.1,
		FindingsTotal: 5,
		RulesTotal:    49,
		Categories: []ruleTiming{
			{Category: "compose", FindingCount: 3, RuleIDs: []string{"exposed_inference", "latest_image", "privileged_container"}},
			{Category: "dockerfile", FindingCount: 2, RuleIDs: []string{"dockerfile_user_root"}},
		},
		BySeverity: map[string]int{"HIGH": 2, "MEDIUM": 2, "CRITICAL": 1},
		Slowest:    "collect",
	}

	if result.FindingsTotal != 5 {
		t.Errorf("expected 5 findings, got %d", result.FindingsTotal)
	}
	if result.Slowest != "collect" {
		t.Errorf("expected slowest=collect, got %s", result.Slowest)
	}
	if len(result.Categories) != 2 {
		t.Errorf("expected 2 categories, got %d", len(result.Categories))
	}
	if result.Categories[0].Category != "compose" {
		t.Errorf("expected first category compose, got %s", result.Categories[0].Category)
	}
}

func TestContainsStr(t *testing.T) {
	if !containsStr([]string{"a", "b", "c"}, "b") {
		t.Error("expected true for existing element")
	}
	if containsStr([]string{"a", "b", "c"}, "d") {
		t.Error("expected false for missing element")
	}
	if containsStr(nil, "a") {
		t.Error("expected false for nil slice")
	}
}

func TestJoinMax(t *testing.T) {
	short := joinMax([]string{"a", "b"}, 3)
	if short != "a, b" {
		t.Errorf("expected 'a, b', got %q", short)
	}
	long := joinMax([]string{"a", "b", "c", "d", "e"}, 2)
	if !strings.Contains(long, "+3 more") {
		t.Errorf("expected '+3 more', got %q", long)
	}
}

func TestJoinStrings(t *testing.T) {
	if joinStrings(nil) != "" {
		t.Error("expected empty for nil")
	}
	if joinStrings([]string{"x"}) != "x" {
		t.Error("expected single element")
	}
	if joinStrings([]string{"a", "b", "c"}) != "a, b, c" {
		t.Error("expected comma-separated")
	}
}
