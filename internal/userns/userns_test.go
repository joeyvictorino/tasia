package userns

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) collect.Collected {
	return collect.Collected{
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: services}},
	}
}

func TestNoServices(t *testing.T) {
	r := Analyze(collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestCleanService(t *testing.T) {
	c := makeCollected(compose.Service{Name: "app", Image: "myapp:latest"})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(r.Services[0].Findings))
	}
	if r.Services[0].Grade != "A" {
		t.Errorf("expected A, got %s", r.Services[0].Grade)
	}
}

func TestUsernsHostMode(t *testing.T) {
	c := makeCollected(compose.Service{Name: "app", UsernsMode: "host"})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "userns_host_mode" {
			found = true
			if f.Severity != "high" {
				t.Errorf("expected high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected userns_host_mode finding")
	}
	if r.Summary.WithUsernsHost != 1 {
		t.Errorf("expected 1 userns host, got %d", r.Summary.WithUsernsHost)
	}
}

func TestPrivilegedNoUserns(t *testing.T) {
	c := makeCollected(compose.Service{Name: "app", Privileged: true})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "privileged_no_userns" {
			found = true
		}
	}
	if !found {
		t.Error("expected privileged_no_userns finding")
	}
}

func TestPrivilegedWithUsernsHost(t *testing.T) {
	c := makeCollected(compose.Service{Name: "app", Privileged: true, UsernsMode: "host"})
	r := Analyze(c)
	categories := map[string]bool{}
	for _, f := range r.Services[0].Findings {
		categories[f.Category] = true
	}
	if !categories["privileged_userns_host"] {
		t.Error("expected privileged_userns_host finding")
	}
	if !categories["userns_host_mode"] {
		t.Error("expected userns_host_mode finding")
	}
	if r.Services[0].Findings[1].Severity != "critical" {
		t.Errorf("expected critical severity for privileged+userns_host")
	}
}

func TestRootWithoutUserns(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"USER=root"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "root_without_userns" {
			found = true
		}
	}
	if !found {
		t.Error("expected root_without_userns finding")
	}
}

func TestSummaryTotals(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", Privileged: true},
		compose.Service{Name: "b", UsernsMode: "host"},
		compose.Service{Name: "c", Image: "clean:latest"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithPrivileged != 1 {
		t.Errorf("expected 1 privileged, got %d", r.Summary.WithPrivileged)
	}
	if r.Summary.WithUsernsHost != 1 {
		t.Errorf("expected 1 userns host, got %d", r.Summary.WithUsernsHost)
	}
}

func TestScoreGrading(t *testing.T) {
	tests := []struct {
		score int
		grade string
	}{
		{100, "A"}, {90, "A"}, {85, "B"}, {75, "C"}, {65, "D"}, {50, "F"},
	}
	for _, tt := range tests {
		got := scoreToGrade(tt.score)
		if got != tt.grade {
			t.Errorf("scoreToGrade(%d) = %s, want %s", tt.score, got, tt.grade)
		}
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := makeCollected(compose.Service{Name: "app", UsernsMode: "host"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "User Namespace Audit") {
		t.Error("expected header in text output")
	}
	if !strings.Contains(text, "userns_mode: host") {
		t.Error("expected userns_mode detail in output")
	}
}

func TestScoreFloor(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "bad",
		Privileged:  true,
		UsernsMode:  "host",
		Environment: []string{"USER=root"},
	})
	r := Analyze(c)
	if r.Services[0].Score < 0 {
		t.Error("score should not go below 0")
	}
}
