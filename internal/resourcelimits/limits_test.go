package resourcelimits

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeFullyGoverned(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:           "agent",
				MemLimit:       "512m",
				CPUs:           "1.0",
				MemReservation: "256m",
				PidsLimit:      100,
				ReadOnly:       true,
			}},
		}},
	}
	r := Analyze(c)
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	if r.Services[0].Score != 100 {
		t.Errorf("expected score 100, got %d", r.Services[0].Score)
	}
	if r.Services[0].Grade != "A" {
		t.Errorf("expected grade A, got %s", r.Services[0].Grade)
	}
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Services[0].Findings))
	}
}

func TestAnalyzeNoLimits(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name: "uncontrolled",
			}},
		}},
	}
	r := Analyze(c)
	svc := r.Services[0]
	if svc.Score != 0 {
		t.Errorf("expected score 0, got %d", svc.Score)
	}
	if svc.Grade != "F" {
		t.Errorf("expected grade F, got %s", svc.Grade)
	}
	if len(svc.Findings) < 4 {
		t.Errorf("expected at least 4 findings, got %d", len(svc.Findings))
	}
}

func TestAnalyzeOverlyGenerous(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:     "big",
				MemLimit: "16g",
				CPUs:     "8.0",
			}},
		}},
	}
	r := Analyze(c)
	svc := r.Services[0]
	found := 0
	for _, f := range svc.Findings {
		if f.Category == "memory" && f.Severity == "medium" {
			found++
		}
		if f.Category == "cpu" && f.Severity == "medium" {
			found++
		}
	}
	if found < 2 {
		t.Errorf("expected 2 overly-generous findings, got %d", found)
	}
}

func TestParseMemoryBytes(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"512m", 512 * 1024 * 1024},
		{"1g", 1024 * 1024 * 1024},
		{"256M", 256 * 1024 * 1024},
		{"2GB", 2 * 1024 * 1024 * 1024},
		{"1024k", 1024 * 1024},
		{"", 0},
		{"invalid", 0},
	}
	for _, tt := range tests {
		got := parseMemoryBytes(tt.input)
		if got != tt.expected {
			t.Errorf("parseMemoryBytes(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestAnalyzePartialLimits(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:     "partial",
				MemLimit: "1g",
				CPUs:     "2.0",
			}},
		}},
	}
	r := Analyze(c)
	svc := r.Services[0]
	if svc.Score < 40 || svc.Score > 60 {
		t.Errorf("expected score 40-60, got %d", svc.Score)
	}
}

func TestSummary(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "good", MemLimit: "512m", CPUs: "1", MemReservation: "256m", PidsLimit: 100, ReadOnly: true},
				{Name: "bad"},
			},
		}},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.Governed != 1 {
		t.Errorf("expected 1 governed, got %d", r.Summary.Governed)
	}
	if r.Summary.Ungoverned != 1 {
		t.Errorf("expected 1 ungoverned, got %d", r.Summary.Ungoverned)
	}
}

func TestFormatText(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{Name: "svc", MemLimit: "1g"}},
		}},
	}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
	if r.Summary.AverageScore != 0 {
		t.Error("expected 0 average score for empty")
	}
}
