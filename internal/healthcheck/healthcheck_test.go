package healthcheck

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services []compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestNoHealthcheck(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web"},
	})
	r := Analyze(c)
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	if r.Services[0].Score != 0 {
		t.Errorf("expected score 0 for no healthcheck, got %d", r.Services[0].Score)
	}
	if r.Services[0].Grade != "F" {
		t.Errorf("expected grade F, got %s", r.Services[0].Grade)
	}
	if len(r.Services[0].Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Services[0].Findings))
	}
	if r.Services[0].Findings[0].Level != "high" {
		t.Errorf("expected high level, got %s", r.Services[0].Findings[0].Level)
	}
}

func TestDisabledHealthcheck(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Healthcheck: &compose.Healthcheck{Disable: true}},
	})
	r := Analyze(c)
	if r.Services[0].Score != 0 {
		t.Errorf("expected score 0, got %d", r.Services[0].Score)
	}
}

func TestNoneTest(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Healthcheck: &compose.Healthcheck{Test: []string{"NONE"}, Disable: true}},
	})
	r := Analyze(c)
	if r.Services[0].Score != 0 {
		t.Errorf("expected score 0, got %d", r.Services[0].Score)
	}
}

func TestGoodHealthcheck(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD", "curl", "-f", "http://localhost/"},
			Interval: "30s",
			Timeout:  "10s",
			Retries:  3,
		}},
	})
	r := Analyze(c)
	if r.Services[0].Score < 80 {
		t.Errorf("expected score >= 80 for good healthcheck, got %d", r.Services[0].Score)
	}
}

func TestCMDShellPenalty(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD-SHELL", "curl -f http://localhost/"},
			Interval: "30s",
			Timeout:  "10s",
			Retries:  3,
		}},
	})
	r := Analyze(c)
	hasShellFinding := false
	for _, f := range r.Services[0].Findings {
		if f.Message == "Healthcheck uses CMD-SHELL; prefer CMD exec form for reliability" {
			hasShellFinding = true
		}
	}
	if !hasShellFinding {
		t.Error("expected CMD-SHELL finding")
	}
}

func TestLongInterval(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD", "true"},
			Interval: "120s",
			Timeout:  "10s",
			Retries:  3,
		}},
	})
	r := Analyze(c)
	hasIntervalFinding := false
	for _, f := range r.Services[0].Findings {
		if f.Level == "medium" {
			hasIntervalFinding = true
		}
	}
	if !hasIntervalFinding {
		t.Error("expected medium finding for long interval")
	}
}

func TestLongStartPeriod(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Healthcheck: &compose.Healthcheck{
			Test:        []string{"CMD", "true"},
			Interval:    "30s",
			Timeout:     "10s",
			Retries:     3,
			StartPeriod: "5m",
		}},
	})
	r := Analyze(c)
	hasStartFinding := false
	for _, f := range r.Services[0].Findings {
		if f.Level == "medium" {
			hasStartFinding = true
		}
	}
	if !hasStartFinding {
		t.Error("expected medium finding for long start period")
	}
}

func TestMissingRetries(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD", "true"},
			Interval: "30s",
			Timeout:  "10s",
		}},
	})
	r := Analyze(c)
	hasRetriesFinding := false
	for _, f := range r.Services[0].Findings {
		if f.Message == "No explicit retries; using Docker default (3)" {
			hasRetriesFinding = true
		}
	}
	if !hasRetriesFinding {
		t.Error("expected retries finding")
	}
}

func TestSummary(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD", "true"},
			Interval: "30s",
			Timeout:  "10s",
			Retries:  3,
		}},
		{Name: "db"},
	})
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 total services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithHealthcheck != 1 {
		t.Errorf("expected 1 with healthcheck, got %d", r.Summary.WithHealthcheck)
	}
}

func TestFormatText(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestNormalizeDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"30s", "30s"},
		{"5m", "5m"},
		{"1h", "1h"},
		{"30", "30s"},
	}
	for _, tt := range tests {
		got := normalizeDuration(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeDuration(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
