package oom

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}},
	}
}

func TestNoServices(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("want 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestNoMemLimit(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "agent"}))
	if r.Summary.ServicesNoLimit != 1 {
		t.Fatalf("want 1 no-limit, got %d", r.Summary.ServicesNoLimit)
	}
	if r.Services[0].Findings[0].RuleID != "oom_no_limit" {
		t.Fatalf("want oom_no_limit, got %s", r.Services[0].Findings[0].RuleID)
	}
}

func TestWithMemLimit(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "agent", MemLimit: "512m"}))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "oom_no_limit" {
			found = true
		}
	}
	if found {
		t.Fatal("should not flag oom_no_limit when mem_limit is set")
	}
}

func TestOomKillDisabled(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "db", MemLimit: "1g", OomKillDisable: true}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "oom_kill_disabled" {
			found = true
			if f.Severity != "high" {
				t.Fatalf("want high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected oom_kill_disabled finding")
	}
}

func TestOomScoreLow(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "critical", MemLimit: "1g",
		OomScoreAdj: -900, OomScoreAdjSet: true,
	}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "oom_score_low" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected oom_score_low finding")
	}
}

func TestOomScoreNormal(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "svc", MemLimit: "1g",
		OomScoreAdj: -200, OomScoreAdjSet: true,
	}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "oom_score_low" {
			t.Fatal("should not flag normal oom_score_adj")
		}
	}
}

func TestNoSwapLimit(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", MemLimit: "512m"}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "oom_no_swap_limit" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected oom_no_swap_limit finding")
	}
}

func TestWithSwapLimit(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", MemLimit: "512m", MemswapLimit: "1g"}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "oom_no_swap_limit" {
			t.Fatal("should not flag when memswap_limit is set")
		}
	}
}

func TestMultipleFindings(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "bad", OomKillDisable: true,
		OomScoreAdj: -800, OomScoreAdjSet: true,
	}))
	if len(r.Services[0].Findings) < 3 {
		t.Fatalf("want >= 3 findings (no_limit + kill_disabled + score_low), got %d", len(r.Services[0].Findings))
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(collected(
		compose.Service{Name: "a"},
		compose.Service{Name: "b", MemLimit: "256m"},
	))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("want 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.ServicesNoLimit != 1 {
		t.Fatalf("want 1 no-limit, got %d", r.Summary.ServicesNoLimit)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", OomKillDisable: true}))
	text := FormatText(r)
	if text == "" {
		t.Fatal("format text should not be empty")
	}
	if !contains(text, "OOM Kill Risk") {
		t.Fatal("should contain header")
	}
}

func TestSummaryCount(t *testing.T) {
	r := Analyze(collected(
		compose.Service{Name: "a", OomKillDisable: true},
		compose.Service{Name: "b", OomKillDisable: true},
	))
	if r.Summary.OomKillDisabled != 2 {
		t.Fatalf("want 2 oom_kill_disabled, got %d", r.Summary.OomKillDisabled)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
