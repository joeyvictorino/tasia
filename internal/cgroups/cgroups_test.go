package cgroups

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services []compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestNoLimits(t *testing.T) {
	c := mkCollected([]compose.Service{{Name: "api"}})
	r := Analyze(c)
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	s := r.Services[0]
	cats := map[string]bool{}
	for _, f := range s.Findings {
		cats[f.Category] = true
	}
	if !cats["no_memory_limit"] {
		t.Error("expected no_memory_limit finding")
	}
	if !cats["no_cpu_limit"] {
		t.Error("expected no_cpu_limit finding")
	}
	if !cats["no_pids_limit"] {
		t.Error("expected no_pids_limit finding")
	}
	if !cats["no_resource_limits"] {
		t.Error("expected no_resource_limits finding")
	}
}

func TestWithAllLimits(t *testing.T) {
	c := mkCollected([]compose.Service{{
		Name:      "api",
		MemLimit:  "512m",
		CPUs:      "2",
		PidsLimit: 100,
	}})
	r := Analyze(c)
	s := r.Services[0]
	if len(s.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %+v", len(s.Findings), s.Findings)
	}
	if s.Grade != "A" {
		t.Errorf("expected grade A, got %s", s.Grade)
	}
}

func TestHighMemoryLimit(t *testing.T) {
	c := mkCollected([]compose.Service{{
		Name:      "worker",
		MemLimit:  "16g",
		CPUs:      "4",
		PidsLimit: 200,
	}})
	r := Analyze(c)
	s := r.Services[0]
	found := false
	for _, f := range s.Findings {
		if f.Category == "high_memory_limit" {
			found = true
		}
	}
	if !found {
		t.Error("expected high_memory_limit finding for 16g")
	}
}

func TestReservationExceedsLimit(t *testing.T) {
	c := mkCollected([]compose.Service{{
		Name:           "db",
		MemLimit:       "256m",
		MemReservation: "512m",
		CPUs:           "1",
		PidsLimit:      50,
	}})
	r := Analyze(c)
	s := r.Services[0]
	found := false
	for _, f := range s.Findings {
		if f.Category == "reservation_exceeds_limit" {
			found = true
		}
	}
	if !found {
		t.Error("expected reservation_exceeds_limit finding")
	}
}

func TestHighCPULimit(t *testing.T) {
	c := mkCollected([]compose.Service{{
		Name:      "compute",
		MemLimit:  "1g",
		CPUs:      "16",
		PidsLimit: 100,
	}})
	r := Analyze(c)
	s := r.Services[0]
	found := false
	for _, f := range s.Findings {
		if f.Category == "high_cpu_limit" {
			found = true
		}
	}
	if !found {
		t.Error("expected high_cpu_limit finding for 16 CPUs")
	}
}

func TestSummaryCountsNoLimits(t *testing.T) {
	c := mkCollected([]compose.Service{
		{Name: "svc1"},
		{Name: "svc2", MemLimit: "256m"},
	})
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithoutMemLimit != 1 {
		t.Errorf("expected 1 without mem limit, got %d", r.Summary.WithoutMemLimit)
	}
}

func TestParseMemoryBytes(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"512m", 512 * 1024 * 1024},
		{"1g", 1024 * 1024 * 1024},
		{"256k", 256 * 1024},
		{"1024", 1024},
		{"2gb", 2 * 1024 * 1024 * 1024},
	}
	for _, tt := range tests {
		got := parseMemoryBytes(tt.input)
		if got != tt.want {
			t.Errorf("parseMemoryBytes(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestScoreGrading(t *testing.T) {
	c := mkCollected([]compose.Service{{Name: "limited", MemLimit: "256m", CPUs: "1", PidsLimit: 50}})
	r := Analyze(c)
	if r.Services[0].Score != 100 {
		t.Errorf("expected score 100, got %d", r.Services[0].Score)
	}
	if r.Services[0].Grade != "A" {
		t.Errorf("expected grade A, got %s", r.Services[0].Grade)
	}
}

func TestFormatText(t *testing.T) {
	c := mkCollected([]compose.Service{{Name: "web"}})
	r := Analyze(c)
	text := FormatText(r)
	if !contains(text, "Cgroup Resource Limits Audit") {
		t.Error("expected header in text output")
	}
	if !contains(text, "web") {
		t.Error("expected service name in text output")
	}
}

func TestMultipleServicesScoring(t *testing.T) {
	c := mkCollected([]compose.Service{
		{Name: "good", MemLimit: "256m", CPUs: "1", PidsLimit: 50},
		{Name: "bad"},
	})
	r := Analyze(c)
	if r.Summary.WithLimits != 1 {
		t.Errorf("expected 1 with limits, got %d", r.Summary.WithLimits)
	}
	if r.Summary.TotalFindings == 0 {
		t.Error("expected findings for bad service")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
