package deploypol

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

func TestNoDeployPolicy(t *testing.T) {
	svc := compose.Service{Name: "app"}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "deploy_no_restart_policy" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected deploy_no_restart_policy finding")
	}
}

func TestUnlimitedRetries(t *testing.T) {
	svc := compose.Service{
		Name: "worker",
		DeployRestartPolicy: &compose.DeployRestartPolicy{
			Condition: "any",
		},
	}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "deploy_unlimited_retries" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected deploy_unlimited_retries for condition:any with no max_attempts")
	}
}

func TestExcessiveRetries(t *testing.T) {
	svc := compose.Service{
		Name: "api",
		DeployRestartPolicy: &compose.DeployRestartPolicy{
			Condition:  "on-failure",
			MaxAttempts: 200,
		},
	}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "deploy_excessive_retries" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected deploy_excessive_retries for 200 max_attempts")
	}
}

func TestNoRestart(t *testing.T) {
	svc := compose.Service{
		Name: "batch",
		DeployRestartPolicy: &compose.DeployRestartPolicy{
			Condition: "none",
		},
	}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "deploy_no_restart" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected deploy_no_restart for condition:none")
	}
}

func TestPrivilegedAlwaysRestart(t *testing.T) {
	svc := compose.Service{
		Name:       "agent",
		Privileged: true,
		DeployRestartPolicy: &compose.DeployRestartPolicy{
			Condition: "any",
		},
	}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "deploy_privileged_always_restart" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected deploy_privileged_always_restart")
	}
}

func TestShortDelay(t *testing.T) {
	svc := compose.Service{
		Name: "web",
		DeployRestartPolicy: &compose.DeployRestartPolicy{
			Condition: "any",
			Delay:     "0s",
		},
	}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "deploy_short_delay" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected deploy_short_delay for 0s delay")
	}
}

func TestReasonablePolicy(t *testing.T) {
	svc := compose.Service{
		Name: "api",
		DeployRestartPolicy: &compose.DeployRestartPolicy{
			Condition:  "on-failure",
			MaxAttempts: 5,
			Delay:      "10s",
		},
	}
	r := Analyze(collected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Level == "high" || f.Level == "medium" {
				t.Errorf("unexpected high/medium finding for reasonable policy: %s", f.Rule)
			}
		}
	}
}

func TestSummary(t *testing.T) {
	svcs := []compose.Service{
		{Name: "a"},
		{Name: "b", DeployRestartPolicy: &compose.DeployRestartPolicy{Condition: "any"}},
		{Name: "c", DeployRestartPolicy: &compose.DeployRestartPolicy{Condition: "on-failure", MaxAttempts: 3}},
	}
	r := Analyze(collected(svcs...))
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.NoDeployPolicy != 1 {
		t.Errorf("expected 1 no-policy, got %d", r.Summary.NoDeployPolicy)
	}
}

func TestFormatText(t *testing.T) {
	svc := compose.Service{
		Name: "app",
		DeployRestartPolicy: &compose.DeployRestartPolicy{
			Condition:  "on-failure",
			MaxAttempts: 5,
		},
	}
	r := Analyze(collected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "Deploy Restart Policy") {
		t.Error("missing header")
	}
	if !strings.Contains(text, "condition=on-failure") {
		t.Error("missing condition in output")
	}
}

func TestIsShortDelay(t *testing.T) {
	tests := []struct {
		delay string
		want  bool
	}{
		{"0s", true},
		{"0", true},
		{"1s", true},
		{"2s", true},
		{"10s", false},
		{"5m", false},
	}
	for _, tt := range tests {
		got := isShortDelay(tt.delay)
		if got != tt.want {
			t.Errorf("isShortDelay(%q) = %v, want %v", tt.delay, got, tt.want)
		}
	}
}
