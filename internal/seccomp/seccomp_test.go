package seccomp

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
		t.Errorf("expected 0, got %d", r.Summary.TotalServices)
	}
}

func TestNoSeccompProfile(t *testing.T) {
	c := makeCollected(compose.Service{Name: "app", Image: "myapp:latest"})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "no_seccomp_profile" {
			found = true
		}
	}
	if !found {
		t.Error("expected no_seccomp_profile finding")
	}
}

func TestSeccompUnconfined(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"seccomp=unconfined"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "seccomp_unconfined" {
			found = true
			if f.Severity != "high" {
				t.Errorf("expected high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected seccomp_unconfined finding")
	}
	if r.Summary.WithUnconfined != 1 {
		t.Errorf("expected 1 unconfined, got %d", r.Summary.WithUnconfined)
	}
}

func TestCustomSeccompProfile(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"seccomp=/path/to/profile.json"},
	})
	r := Analyze(c)
	if r.Services[0].SeccompProfile != "/path/to/profile.json" {
		t.Errorf("expected custom profile path, got %s", r.Services[0].SeccompProfile)
	}
	if r.Summary.WithCustomProfile != 1 {
		t.Errorf("expected 1 custom, got %d", r.Summary.WithCustomProfile)
	}
	hasUnconfined := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "seccomp_unconfined" {
			hasUnconfined = true
		}
	}
	if hasUnconfined {
		t.Error("custom profile should not trigger unconfined finding")
	}
}

func TestPrivilegedBypassesSeccomp(t *testing.T) {
	c := makeCollected(compose.Service{Name: "app", Privileged: true})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "privileged_bypasses_seccomp" {
			found = true
		}
	}
	if !found {
		t.Error("expected privileged_bypasses_seccomp finding")
	}
}

func TestPrivilegedUnconfined(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Privileged:  true,
		SecurityOpt: []string{"seccomp=unconfined"},
	})
	r := Analyze(c)
	categories := map[string]bool{}
	for _, f := range r.Services[0].Findings {
		categories[f.Category] = true
	}
	if !categories["privileged_unconfined"] {
		t.Error("expected privileged_unconfined finding")
	}
}

func TestAppArmorDisabled(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"apparmor=unconfined", "seccomp=/profile.json"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "apparmor_disabled" {
			found = true
		}
	}
	if !found {
		t.Error("expected apparmor_disabled finding")
	}
}

func TestNoNewPrivilegesDisabled(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"no-new-privileges:false", "seccomp=/profile.json"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "no_new_privileges_disabled" {
			found = true
		}
	}
	if !found {
		t.Error("expected no_new_privileges_disabled finding")
	}
}

func TestSummaryTotals(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", SecurityOpt: []string{"seccomp=unconfined"}},
		compose.Service{Name: "b", SecurityOpt: []string{"seccomp=/custom.json"}},
		compose.Service{Name: "c", Image: "clean:latest"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithSeccomp != 2 {
		t.Errorf("expected 2 with seccomp, got %d", r.Summary.WithSeccomp)
	}
	if r.Summary.WithNoSeccomp != 1 {
		t.Errorf("expected 1 with no seccomp, got %d", r.Summary.WithNoSeccomp)
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
	c := makeCollected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"seccomp=unconfined"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Seccomp Profile Audit") {
		t.Error("expected header in text output")
	}
	if !strings.Contains(text, "seccomp: unconfined") {
		t.Error("expected seccomp profile in output")
	}
}

func TestExtractSeccompProfile(t *testing.T) {
	tests := []struct {
		opts   []string
		expect string
	}{
		{[]string{"seccomp=unconfined"}, "unconfined"},
		{[]string{"seccomp=/path/to/profile.json"}, "/path/to/profile.json"},
		{[]string{"seccomp:unconfined"}, "unconfined"},
		{[]string{"apparmor=unconfined"}, ""},
		{nil, ""},
	}
	for _, tt := range tests {
		got := extractSeccompProfile(tt.opts)
		if got != tt.expect {
			t.Errorf("extractSeccompProfile(%v) = %q, want %q", tt.opts, got, tt.expect)
		}
	}
}

func TestScoreFloor(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "bad",
		Privileged:  true,
		SecurityOpt: []string{"seccomp=unconfined", "apparmor=unconfined", "no-new-privileges:false"},
	})
	r := Analyze(c)
	if r.Services[0].Score < 0 {
		t.Error("score should not go below 0")
	}
}
