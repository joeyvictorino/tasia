package healthprobe

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

func TestNoHealthcheck(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "app"},
			},
		}},
	}
	r := Analyze(c)
	if r.Summary.WithoutHealthcheck != 1 {
		t.Fatalf("expected 1 without healthcheck, got %d", r.Summary.WithoutHealthcheck)
	}
	found := false
	for _, f := range r.Findings {
		if f.Category == "no-healthcheck" && f.Service == "app" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected no-healthcheck finding")
	}
}

func TestDisabledHealthcheck(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "db", Healthcheck: &compose.Healthcheck{Disable: true}},
			},
		}},
	}
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Category == "healthcheck-disabled" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected healthcheck-disabled finding")
	}
}

func TestCompleteHealthcheck(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "api", Healthcheck: &compose.Healthcheck{
					Test:        []string{"CMD", "curl", "--fail", "http://localhost:8080/health"},
					Interval:    "10s",
					Timeout:     "5s",
					Retries:     3,
					StartPeriod: "30s",
				}},
			},
		}},
	}
	r := Analyze(c)
	if r.Summary.WithHealthcheck != 1 {
		t.Fatalf("expected 1 with healthcheck, got %d", r.Summary.WithHealthcheck)
	}
	for _, f := range r.Findings {
		if f.Service == "api" && f.Category != "curl-no-fail" {
			if f.Category == "missing-interval" || f.Category == "missing-timeout" ||
				f.Category == "missing-retries" || f.Category == "missing-start-period" {
				t.Fatalf("unexpected missing finding: %s", f.Category)
			}
		}
	}
}

func TestCurlWithoutFail(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "web", Healthcheck: &compose.Healthcheck{
					Test:     []string{"CMD", "curl", "http://localhost/health"},
					Interval: "10s",
					Timeout:  "5s",
					Retries:  3,
				}},
			},
		}},
	}
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Category == "curl-no-fail" && f.Service == "web" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected curl-no-fail finding")
	}
}

func TestMissingFields(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "svc", Healthcheck: &compose.Healthcheck{
					Test: []string{"CMD", "true"},
				}},
			},
		}},
	}
	r := Analyze(c)
	categories := map[string]bool{}
	for _, f := range r.Findings {
		categories[f.Category] = true
	}
	for _, cat := range []string{"missing-interval", "missing-timeout", "missing-retries", "missing-start-period"} {
		if !categories[cat] {
			t.Errorf("expected finding category %s", cat)
		}
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Analyze(&collect.Collected{})
	out := FormatText(r)
	if !strings.Contains(out, "Health Probe Analysis") {
		t.Fatal("expected header in text output")
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

func TestMultipleServices(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "a", Healthcheck: &compose.Healthcheck{
					Test: []string{"CMD", "true"}, Interval: "10s", Timeout: "5s", Retries: 3, StartPeriod: "5s",
				}},
				{Name: "b"},
				{Name: "c"},
			},
		}},
	}
	r := Analyze(c)
	if r.Summary.WithHealthcheck != 1 {
		t.Fatalf("expected 1 with healthcheck, got %d", r.Summary.WithHealthcheck)
	}
	if r.Summary.WithoutHealthcheck != 2 {
		t.Fatalf("expected 2 without healthcheck, got %d", r.Summary.WithoutHealthcheck)
	}
}
