package restartpol

import (
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

func TestMissingPolicy(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc"}))
	if r.Summary.NoPolicy != 1 {
		t.Fatalf("want 1 missing, got %d", r.Summary.NoPolicy)
	}
	if r.Services[0].Findings[0].RuleID != "restart_missing" {
		t.Fatalf("want restart_missing, got %s", r.Services[0].Findings[0].RuleID)
	}
}

func TestAlwaysRestart(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "agent", Restart: "always"}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "restart_always_agent" {
			found = true
			if f.Severity != "medium" {
				t.Fatalf("want medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected restart_always_agent")
	}
}

func TestUnlessStopped(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", Restart: "unless-stopped"}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "restart_always_agent" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected finding for unless-stopped")
	}
}

func TestOnFailureNoFinding(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", Restart: "on-failure"}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "restart_always_agent" || f.RuleID == "restart_missing" {
			t.Fatalf("unexpected finding %s for on-failure", f.RuleID)
		}
	}
}

func TestDeployNoMaxAttempts(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "svc", Restart: "no",
		DeployRestartPolicy: &compose.DeployRestartPolicy{Condition: "on-failure"},
	}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "restart_no_limit" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected restart_no_limit")
	}
}

func TestDeployHighMaxAttempts(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "svc", Restart: "no",
		DeployRestartPolicy: &compose.DeployRestartPolicy{Condition: "on-failure", MaxAttempts: 20},
	}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "restart_no_limit" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected restart_no_limit for high max_attempts")
	}
}

func TestDeployReasonableMaxAttempts(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "svc", Restart: "no",
		DeployRestartPolicy: &compose.DeployRestartPolicy{Condition: "on-failure", MaxAttempts: 5},
	}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "restart_no_limit" {
			t.Fatal("should not flag reasonable max_attempts")
		}
	}
}

func TestDeployRapidDelay(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "svc", Restart: "no",
		DeployRestartPolicy: &compose.DeployRestartPolicy{Condition: "on-failure", MaxAttempts: 5, Delay: "1s"},
	}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "restart_rapid" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected restart_rapid for 1s delay")
	}
}

func TestDeployMillisecondDelay(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "svc", Restart: "no",
		DeployRestartPolicy: &compose.DeployRestartPolicy{Condition: "on-failure", MaxAttempts: 5, Delay: "500ms"},
	}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "restart_rapid" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected restart_rapid for millisecond delay")
	}
}

func TestDeployNormalDelay(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "svc", Restart: "no",
		DeployRestartPolicy: &compose.DeployRestartPolicy{Condition: "on-failure", MaxAttempts: 5, Delay: "10s"},
	}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "restart_rapid" {
			t.Fatal("should not flag 10s delay")
		}
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(collected(
		compose.Service{Name: "a", Restart: "always"},
		compose.Service{Name: "b"},
	))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("want 2, got %d", r.Summary.TotalServices)
	}
	if r.Summary.AlwaysRestart != 1 {
		t.Fatalf("want 1 always, got %d", r.Summary.AlwaysRestart)
	}
	if r.Summary.NoPolicy != 1 {
		t.Fatalf("want 1 missing, got %d", r.Summary.NoPolicy)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", Restart: "always"}))
	text := FormatText(r)
	if text == "" {
		t.Fatal("format text should not be empty")
	}
	if !contains(text, "Restart Policy") {
		t.Fatal("should contain header")
	}
}

func TestIsRapidDelay(t *testing.T) {
	tests := []struct {
		delay string
		want  bool
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
		got := isRapidDelay(tt.delay)
		if got != tt.want {
			t.Errorf("isRapidDelay(%q) = %v, want %v", tt.delay, got, tt.want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
