package stopgrace

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}},
	}
}

func TestNoServices(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("want 0, got %d", r.Summary.TotalServices)
	}
}

func TestSigkillSignal(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", StopSignal: "SIGKILL"}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "stop_sigkill" {
			found = true
			if f.Severity != "high" {
				t.Fatalf("want high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected stop_sigkill finding")
	}
}

func TestNumericKillSignal(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", StopSignal: "9"}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "stop_sigkill" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected stop_sigkill for signal 9")
	}
}

func TestSigtermNoFinding(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", StopSignal: "SIGTERM"}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "stop_sigkill" {
			t.Fatal("should not flag SIGTERM")
		}
	}
}

func TestMissingGracePeriod(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", StopSignal: "SIGUSR1"}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "stop_grace_missing" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected stop_grace_missing when custom signal set without grace period")
	}
}

func TestShortGracePeriod(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", StopGracePeriod: "2s"}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "stop_grace_short" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected stop_grace_short for 2s")
	}
}

func TestShortGraceMilliseconds(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", StopGracePeriod: "500ms"}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "stop_grace_short" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected stop_grace_short for 500ms")
	}
}

func TestNormalGracePeriod(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", StopGracePeriod: "30s"}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "stop_grace_short" || f.RuleID == "stop_grace_long" {
			t.Fatalf("should not flag 30s grace period, got %s", f.RuleID)
		}
	}
}

func TestLongGracePeriod(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", StopGracePeriod: "300s"}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "stop_grace_long" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected stop_grace_long for 300s")
	}
}

func TestLongGraceMinutes(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", StopGracePeriod: "5m"}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "stop_grace_long" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected stop_grace_long for 5m")
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(collected(
		compose.Service{Name: "a", StopSignal: "SIGKILL"},
		compose.Service{Name: "b", StopGracePeriod: "1s"},
	))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("want 2, got %d", r.Summary.TotalServices)
	}
	if r.Summary.SigkillSignal != 1 {
		t.Fatalf("want 1 sigkill, got %d", r.Summary.SigkillSignal)
	}
	if r.Summary.ShortGrace != 1 {
		t.Fatalf("want 1 short grace, got %d", r.Summary.ShortGrace)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", StopSignal: "SIGKILL"}))
	text := FormatText(r)
	if text == "" {
		t.Fatal("format text should not be empty")
	}
	if !strings.Contains(text, "Stop Signal") {
		t.Fatal("should contain header")
	}
}

func TestIsShortGrace(t *testing.T) {
	tests := []struct {
		d    string
		want bool
	}{
		{"1s", true},
		{"4s", true},
		{"5s", false},
		{"10s", false},
		{"500ms", true},
		{"3", true},
		{"10", false},
	}
	for _, tt := range tests {
		got := isShortGrace(tt.d)
		if got != tt.want {
			t.Errorf("isShortGrace(%q) = %v, want %v", tt.d, got, tt.want)
		}
	}
}

func TestIsLongGrace(t *testing.T) {
	tests := []struct {
		d    string
		want bool
	}{
		{"30s", false},
		{"120s", false},
		{"121s", true},
		{"300s", true},
		{"2m", false},
		{"3m", true},
		{"5m", true},
	}
	for _, tt := range tests {
		got := isLongGrace(tt.d)
		if got != tt.want {
			t.Errorf("isLongGrace(%q) = %v, want %v", tt.d, got, tt.want)
		}
	}
}
