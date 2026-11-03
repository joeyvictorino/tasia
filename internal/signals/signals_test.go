package signals

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

func TestNoInitProcess(t *testing.T) {
	c := mkCollected([]compose.Service{{Name: "api", Image: "python:3.11"}})
	r := Analyze(c)
	s := r.Services[0]
	found := false
	for _, f := range s.Findings {
		if f.Category == "no_init_process" {
			found = true
		}
	}
	if !found {
		t.Error("expected no_init_process finding")
	}
}

func TestTiniImage(t *testing.T) {
	c := mkCollected([]compose.Service{{Name: "api", Image: "myapp-tini:latest"}})
	r := Analyze(c)
	s := r.Services[0]
	if !s.HasInit {
		t.Error("expected HasInit=true for tini image")
	}
	for _, f := range s.Findings {
		if f.Category == "no_init_process" {
			t.Error("should not flag no_init_process for tini image")
		}
	}
}

func TestDangerousStopSignal(t *testing.T) {
	c := mkCollected([]compose.Service{{
		Name:        "worker",
		Environment: []string{"STOPSIGNAL=SIGKILL"},
	}})
	r := Analyze(c)
	s := r.Services[0]
	found := false
	for _, f := range s.Findings {
		if f.Category == "dangerous_stop_signal" {
			found = true
		}
	}
	if !found {
		t.Error("expected dangerous_stop_signal finding for SIGKILL")
	}
}

func TestShortGracePeriod(t *testing.T) {
	c := mkCollected([]compose.Service{{
		Name:        "api",
		Environment: []string{"STOP_GRACE_PERIOD=2s"},
		Labels:      map[string]string{"com.docker.compose.init": "true"},
	}})
	r := Analyze(c)
	s := r.Services[0]
	found := false
	for _, f := range s.Findings {
		if f.Category == "short_grace_period" {
			found = true
		}
	}
	if !found {
		t.Error("expected short_grace_period finding for 2s")
	}
}

func TestLongGracePeriod(t *testing.T) {
	c := mkCollected([]compose.Service{{
		Name:        "db",
		Environment: []string{"STOP_GRACE_PERIOD=5m"},
		Labels:      map[string]string{"com.docker.compose.init": "true"},
	}})
	r := Analyze(c)
	s := r.Services[0]
	found := false
	for _, f := range s.Findings {
		if f.Category == "long_grace_period" {
			found = true
		}
	}
	if !found {
		t.Error("expected long_grace_period finding for 5m")
	}
}

func TestPrivilegedNoStopSignal(t *testing.T) {
	c := mkCollected([]compose.Service{{
		Name:       "agent",
		Privileged: true,
		Labels:     map[string]string{"com.docker.compose.init": "true"},
	}})
	r := Analyze(c)
	s := r.Services[0]
	found := false
	for _, f := range s.Findings {
		if f.Category == "privileged_no_stop_signal" {
			found = true
		}
	}
	if !found {
		t.Error("expected privileged_no_stop_signal finding")
	}
}

func TestCleanService(t *testing.T) {
	c := mkCollected([]compose.Service{{
		Name:   "clean",
		Image:  "myapp-tini:latest",
		Labels: map[string]string{},
	}})
	r := Analyze(c)
	s := r.Services[0]
	if s.Grade != "A" {
		t.Errorf("expected grade A for clean service, got %s (findings: %+v)", s.Grade, s.Findings)
	}
}

func TestSummary(t *testing.T) {
	c := mkCollected([]compose.Service{
		{Name: "a", Environment: []string{"STOPSIGNAL=SIGTERM"}, Labels: map[string]string{"com.docker.compose.init": "true"}},
		{Name: "b", Image: "plain:1.0"},
	})
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithStopSignal != 1 {
		t.Errorf("expected 1 with stop signal, got %d", r.Summary.WithStopSignal)
	}
	if r.Summary.WithInit != 1 {
		t.Errorf("expected 1 with init, got %d", r.Summary.WithInit)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected([]compose.Service{{Name: "web", Image: "node:20"}})
	r := Analyze(c)
	text := FormatText(r)
	if !containsStr(text, "Signal Handling Audit") {
		t.Error("expected header in text output")
	}
}

func TestParseDurationSeconds(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"10s", 10},
		{"2m", 120},
		{"500ms", 0},
		{"30", 30},
	}
	for _, tt := range tests {
		got := parseDurationSeconds(tt.input)
		if got != tt.want {
			t.Errorf("parseDurationSeconds(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestUnusualStopSignal(t *testing.T) {
	c := mkCollected([]compose.Service{{
		Name:        "custom",
		Environment: []string{"STOPSIGNAL=SIGRTMIN+3"},
		Labels:      map[string]string{"com.docker.compose.init": "true"},
	}})
	r := Analyze(c)
	s := r.Services[0]
	found := false
	for _, f := range s.Findings {
		if f.Category == "unusual_stop_signal" {
			found = true
		}
	}
	if !found {
		t.Error("expected unusual_stop_signal finding for SIGRTMIN+3")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
