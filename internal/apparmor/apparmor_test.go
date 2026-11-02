package apparmor

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

func TestMissingProfile(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "app"}))
	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
	if r.Services[0].Findings[0].RuleID != "apparmor_missing" {
		t.Fatalf("expected apparmor_missing, got %s", r.Services[0].Findings[0].RuleID)
	}
	if r.Summary.WithoutProfile != 1 {
		t.Fatalf("expected 1 without profile, got %d", r.Summary.WithoutProfile)
	}
}

func TestUnconfinedProfile(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"apparmor=unconfined"},
	}))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "apparmor_unconfined" {
			found = true
			if f.Severity != "high" {
				t.Fatalf("expected high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected apparmor_unconfined finding")
	}
	if r.Summary.Unconfined != 1 {
		t.Fatalf("expected 1 unconfined, got %d", r.Summary.Unconfined)
	}
}

func TestDockerDefaultProfile(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"apparmor=docker-default"},
	}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "apparmor_missing" || f.RuleID == "apparmor_unconfined" {
			t.Fatalf("unexpected finding %s for docker-default profile", f.RuleID)
		}
	}
	if r.Summary.WithProfile != 1 {
		t.Fatalf("expected 1 with profile, got %d", r.Summary.WithProfile)
	}
}

func TestCustomProfile(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"apparmor=my-custom-profile"},
	}))
	if r.Services[0].Profile != "my-custom-profile" {
		t.Fatalf("expected my-custom-profile, got %s", r.Services[0].Profile)
	}
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "apparmor_missing" {
			t.Fatal("should not flag missing for custom profile")
		}
	}
}

func TestPrivilegedBypassesAppArmor(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"apparmor=docker-default"},
		Privileged:  true,
	}))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "apparmor_privileged" {
			found = true
			if f.Severity != "critical" {
				t.Fatalf("expected critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected apparmor_privileged finding")
	}
}

func TestColonSyntax(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"apparmor:my-profile"},
	}))
	if r.Services[0].Profile != "my-profile" {
		t.Fatalf("expected my-profile, got %s", r.Services[0].Profile)
	}
}

func TestUnknownSecOpt(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"apparmor=docker-default", "mysterious-option"},
	}))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "apparmor_unknown_secopt" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected apparmor_unknown_secopt finding")
	}
}

func TestNoNewPrivilegesIgnored(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"apparmor=docker-default", "no-new-privileges"},
	}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "apparmor_unknown_secopt" {
			t.Fatal("no-new-privileges should not be flagged as unknown")
		}
	}
	_ = r
}

func TestSeccompIgnored(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"apparmor=docker-default", "seccomp=custom.json"},
	}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "apparmor_unknown_secopt" {
			t.Fatal("seccomp should not be flagged as unknown")
		}
	}
	_ = r
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(collected(
		compose.Service{Name: "web", SecurityOpt: []string{"apparmor=docker-default"}},
		compose.Service{Name: "db"},
		compose.Service{Name: "cache", SecurityOpt: []string{"apparmor=unconfined"}},
	))
	if r.Summary.TotalServices != 3 {
		t.Fatalf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithProfile != 2 {
		t.Fatalf("expected 2 with profile, got %d", r.Summary.WithProfile)
	}
	if r.Summary.WithoutProfile != 1 {
		t.Fatalf("expected 1 without profile, got %d", r.Summary.WithoutProfile)
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
		SecurityOpt: []string{"apparmor=docker-default"},
	}))
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text output")
	}
}

func TestLabelSecOptIgnored(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:        "app",
		SecurityOpt: []string{"apparmor=docker-default", "label:disable"},
	}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "apparmor_unknown_secopt" {
			t.Fatal("label opts should not be flagged as unknown")
		}
	}
}
