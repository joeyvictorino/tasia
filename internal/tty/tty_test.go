package tty

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestInteractive(t *testing.T) {
	svc := compose.Service{Name: "dev", Tty: true, StdinOpen: true}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "tty_interactive" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected tty_interactive finding")
	}
}

func TestTtyOnly(t *testing.T) {
	svc := compose.Service{Name: "app", Tty: true}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "tty_enabled" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected tty_enabled finding")
	}
}

func TestStdinOnly(t *testing.T) {
	svc := compose.Service{Name: "app", StdinOpen: true}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "tty_stdin_open" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected tty_stdin_open finding")
	}
}

func TestProductionTty(t *testing.T) {
	svc := compose.Service{Name: "db", Image: "postgres:15", Tty: true}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "tty_production" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected tty_production finding for postgres with tty")
	}
}

func TestPrivilegedTty(t *testing.T) {
	svc := compose.Service{Name: "agent", Tty: true, Privileged: true}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "tty_privileged" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected tty_privileged finding")
	}
}

func TestNonInteractive(t *testing.T) {
	svc := compose.Service{Name: "worker"}
	r := Analyze(collected(svc))
	for _, sr := range r.Services {
		if len(sr.Findings) != 0 {
			t.Error("expected no findings for non-interactive service")
		}
	}
}

func TestSummary(t *testing.T) {
	svcs := []compose.Service{
		{Name: "a", Tty: true, StdinOpen: true},
		{Name: "b", Tty: true},
		{Name: "c"},
	}
	r := Analyze(collected(svcs...))
	if r.Summary.TtyEnabled != 2 {
		t.Errorf("expected 2 tty, got %d", r.Summary.TtyEnabled)
	}
	if r.Summary.Interactive != 1 {
		t.Errorf("expected 1 interactive, got %d", r.Summary.Interactive)
	}
}

func TestFormatText(t *testing.T) {
	svc := compose.Service{Name: "app", Tty: true}
	r := Analyze(collected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "TTY") {
		t.Error("missing header")
	}
	if !strings.Contains(text, "tty=true") {
		t.Error("missing tty flag in output")
	}
}

func TestIsProductionService(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"postgres:15", true},
		{"redis:7-alpine", true},
		{"myapp:latest", false},
		{"nginx:1.25", true},
	}
	for _, tt := range tests {
		svc := compose.Service{Image: tt.image}
		got := isProductionService(svc)
		if got != tt.want {
			t.Errorf("isProductionService(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}
