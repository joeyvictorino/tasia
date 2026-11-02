package isolation

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeWellHardenedService(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:        "secure-app",
				Privileged:  false,
				CapDrop:     []string{"ALL"},
				CapAdd:      []string{"NET_BIND_SERVICE"},
				NetworkMode: "bridge",
				SecurityOpt: []string{
					"seccomp:custom.json",
					"apparmor:docker-default",
					"no-new-privileges:true",
				},
				Volumes: []string{"data:/app/data"},
			}},
		}},
	}
	r := Analyze(c)
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	svc := r.Services[0]
	if svc.Score < 90 {
		t.Errorf("well-hardened service should score >= 90, got %d", svc.Score)
	}
	if svc.Grade != "A" {
		t.Errorf("expected grade A, got %s", svc.Grade)
	}
}

func TestAnalyzePrivilegedService(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:       "risky-app",
				Privileged: true,
				CapAdd:     []string{"SYS_ADMIN"},
				Volumes:    []string{"/var/run/docker.sock:/var/run/docker.sock"},
			}},
		}},
	}
	r := Analyze(c)
	svc := r.Services[0]
	if svc.Score > 30 {
		t.Errorf("privileged service with dangerous caps should score low, got %d", svc.Score)
	}
	if !svc.Breakdown["not_privileged"].Passed {
		// Expected: should NOT pass
	}
	if svc.Breakdown["not_privileged"].Passed {
		t.Error("expected not_privileged check to fail for privileged container")
	}
	if svc.Breakdown["no_dangerous_caps"].Passed {
		t.Error("expected no_dangerous_caps to fail for SYS_ADMIN")
	}
	if svc.Breakdown["no_sensitive_mounts"].Passed {
		t.Error("expected no_sensitive_mounts to fail for docker.sock mount")
	}
}

func TestAnalyzeHostNetworkMode(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:        "host-net",
				NetworkMode: "host",
			}},
		}},
	}
	r := Analyze(c)
	svc := r.Services[0]
	if svc.Breakdown["no_host_network"].Passed {
		t.Error("expected no_host_network to fail for network_mode: host")
	}
}

func TestAnalyzeEmptyServices(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestAnalyzeMultipleServices(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{
					Name:    "good",
					CapDrop: []string{"ALL"},
					SecurityOpt: []string{
						"seccomp:default.json",
						"apparmor:docker-default",
						"no-new-privileges:true",
					},
				},
				{
					Name:       "bad",
					Privileged: true,
					CapAdd:     []string{"ALL"},
				},
			},
		}},
	}
	r := Analyze(c)
	if len(r.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(r.Services))
	}
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected summary total 2, got %d", r.Summary.TotalServices)
	}
	if r.Summary.MinScore >= r.Summary.MaxScore {
		t.Error("expected min < max for mixed services")
	}
}

func TestGradeFromScore(t *testing.T) {
	tests := []struct {
		score int
		grade string
	}{
		{100, "A"},
		{90, "A"},
		{85, "B"},
		{80, "B"},
		{60, "C"},
		{40, "D"},
		{20, "F"},
		{0, "F"},
	}
	for _, tt := range tests {
		got := gradeFromScore(tt.score)
		if got != tt.grade {
			t.Errorf("gradeFromScore(%d) = %s, want %s", tt.score, got, tt.grade)
		}
	}
}

func TestHasSensitiveMount(t *testing.T) {
	tests := []struct {
		vols []string
		want bool
	}{
		{[]string{"/var/run/docker.sock:/var/run/docker.sock"}, true},
		{[]string{"/proc:/host/proc:ro"}, true},
		{[]string{"/sys:/host/sys:ro"}, true},
		{[]string{"/dev:/dev"}, true},
		{[]string{"data:/app/data"}, false},
		{[]string{"/home/user/app:/app"}, false},
		{nil, false},
	}
	for _, tt := range tests {
		got := hasSensitiveMount(tt.vols)
		if got != tt.want {
			t.Errorf("hasSensitiveMount(%v) = %v, want %v", tt.vols, got, tt.want)
		}
	}
}

func TestHasDangerousCaps(t *testing.T) {
	tests := []struct {
		caps []string
		want bool
	}{
		{[]string{"SYS_ADMIN"}, true},
		{[]string{"NET_BIND_SERVICE"}, false},
		{[]string{"all"}, true},
		{nil, false},
	}
	for _, tt := range tests {
		got := hasDangerousCaps(tt.caps)
		if got != tt.want {
			t.Errorf("hasDangerousCaps(%v) = %v, want %v", tt.caps, got, tt.want)
		}
	}
}

func TestFormatText(t *testing.T) {
	r := Report{
		Services: []ServiceScore{{
			Service: "test-svc",
			File:    "docker-compose.yml",
			Score:   80,
			Grade:   "B",
			Breakdown: map[string]Check{
				"not_privileged": {Passed: true, Points: 20, Description: "Not privileged"},
			},
		}},
		Summary: Summary{TotalServices: 1, AverageScore: 80},
	}
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}
