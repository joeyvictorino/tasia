package selinux

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestNoServices(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestNoLabels(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "app"}))
	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
	if r.Services[0].Findings[0].RuleID != "selinux_no_labels" {
		t.Fatalf("expected selinux_no_labels, got %s", r.Services[0].Findings[0].RuleID)
	}
	if r.Summary.WithoutLabels != 1 {
		t.Fatalf("expected 1 without labels, got %d", r.Summary.WithoutLabels)
	}
}

func TestDisabledLabeling(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"label:disable"},
	}))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "selinux_disabled" {
			found = true
			if f.Severity != "high" {
				t.Fatalf("expected high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected selinux_disabled finding")
	}
	if r.Summary.Disabled != 1 {
		t.Fatalf("expected 1 disabled, got %d", r.Summary.Disabled)
	}
}

func TestWithTypeLabel(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"label:type:container_t"},
	}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "selinux_no_labels" {
			t.Fatal("should not flag missing labels when type is set")
		}
	}
	if r.Summary.WithLabels != 1 {
		t.Fatalf("expected 1 with labels, got %d", r.Summary.WithLabels)
	}
}

func TestPermissiveType(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"label:type:my_permissive_t"},
	}))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "selinux_permissive_type" {
			found = true
			if f.Severity != "high" {
				t.Fatalf("expected high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected selinux_permissive_type finding")
	}
}

func TestMCSCategories(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"label:level:s0"},
	}))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "selinux_no_mcs" {
			found = true
			if f.Severity != "low" {
				t.Fatalf("expected low severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected selinux_no_mcs finding")
	}
}

func TestMCSCategoriesPresent(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"label:level:s0:c100,c200"},
	}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "selinux_no_mcs" {
			t.Fatal("should not flag MCS when categories present")
		}
	}
}

func TestPrivilegedBypassesSELinux(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"label:type:container_t"},
		Privileged:  true,
	}))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "selinux_privileged" {
			found = true
			if f.Severity != "critical" {
				t.Fatalf("expected critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected selinux_privileged finding")
	}
}

func TestEqualsSyntax(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"label=type:container_t"},
	}))
	if len(r.Services[0].Labels) != 1 {
		t.Fatalf("expected 1 label, got %d", len(r.Services[0].Labels))
	}
	if r.Services[0].Labels[0] != "type:container_t" {
		t.Fatalf("expected type:container_t, got %s", r.Services[0].Labels[0])
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(collected(
		compose.Service{Name: "web", SecurityOpt: []string{"label:type:container_t"}},
		compose.Service{Name: "db"},
		compose.Service{Name: "cache", SecurityOpt: []string{"label:disable"}},
	))
	if r.Summary.TotalServices != 3 {
		t.Fatalf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithLabels != 2 {
		t.Fatalf("expected 2 with labels, got %d", r.Summary.WithLabels)
	}
	if r.Summary.WithoutLabels != 1 {
		t.Fatalf("expected 1 without labels, got %d", r.Summary.WithoutLabels)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "app"}))
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text output")
	}
	if len(text) < 10 {
		t.Fatal("text too short")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"label:type:container_t", "label:level:s0:c100,c200"},
	}))
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text output")
	}
}

func TestDisabledCountsAsWithLabels(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"label:disable"},
	}))
	if r.Summary.WithLabels != 1 {
		t.Fatalf("expected disabled to count as with labels, got %d", r.Summary.WithLabels)
	}
}
