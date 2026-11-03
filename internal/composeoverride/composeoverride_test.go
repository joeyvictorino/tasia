package composeoverride

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(path string, svcs []compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: path, Services: svcs},
		},
	}
}

func TestAnalyzeNoOverride(t *testing.T) {
	c := makeCollected("docker-compose.yml", []compose.Service{
		{Name: "web", Image: "nginx:latest"},
	})
	r := Analyze(c)
	if r.Summary.OverrideFiles != 0 {
		t.Fatalf("expected 0 override files, got %d", r.Summary.OverrideFiles)
	}
}

func TestAnalyzePrivileged(t *testing.T) {
	c := makeCollected("docker-compose.override.yml", []compose.Service{
		{Name: "app", Image: "myapp", Privileged: true},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for privileged override")
	}
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "override_privileged" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected override_privileged finding")
	}
}

func TestAnalyzeHostNetwork(t *testing.T) {
	c := makeCollected("docker-compose.override.yml", []compose.Service{
		{Name: "api", Image: "api:latest", NetworkMode: "host"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "override_host_network" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected override_host_network finding")
	}
}

func TestAnalyzeSensitiveVolume(t *testing.T) {
	c := makeCollected("docker-compose.override.yml", []compose.Service{
		{Name: "tools", Image: "tools:latest", Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"}},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "override_sensitive_volume" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected override_sensitive_volume finding")
	}
}

func TestAnalyzeDebugPort(t *testing.T) {
	c := makeCollected("docker-compose.override.yaml", []compose.Service{
		{Name: "debug", Image: "app:dev", Ports: []compose.PortMapping{{Raw: "9229:9229", HostPort: 9229, TargetPort: 9229}}},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "override_debug_port" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected override_debug_port finding")
	}
}

func TestAnalyzeSecurityOpt(t *testing.T) {
	c := makeCollected("docker-compose.override.yml", []compose.Service{
		{Name: "app", Image: "app:latest", SecurityOpt: []string{"seccomp:unconfined"}},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "override_security_opt" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected override_security_opt finding")
	}
}

func TestAnalyzeHostPID(t *testing.T) {
	c := makeCollected("docker-compose.override.yml", []compose.Service{
		{Name: "debug", Image: "debug:latest", PidMode: "host"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "override_host_pid" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected override_host_pid finding")
	}
}

func TestAnalyzeCleanOverride(t *testing.T) {
	c := makeCollected("docker-compose.override.yml", []compose.Service{
		{Name: "app", Image: "app:latest"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
	if r.Summary.Score != 100 {
		t.Fatalf("expected score 100, got %d", r.Summary.Score)
	}
}

func TestFormatText(t *testing.T) {
	r := Report{Summary: Summary{Score: 100}}
	out := FormatText(r)
	if !strings.Contains(out, "Compose Override Security Report") {
		t.Fatal("expected header")
	}
}

func TestIsOverrideFile(t *testing.T) {
	cases := map[string]bool{
		"docker-compose.override.yml": true,
		"docker-compose.yml":          false,
		"compose.dev.yml":             true,
		"compose.local.yaml":          true,
		"compose.prod.yml":            false,
	}
	for path, want := range cases {
		if got := isOverrideFile(path); got != want {
			t.Errorf("isOverrideFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestReadOnlyVolumeNotFlagged(t *testing.T) {
	c := makeCollected("docker-compose.override.yml", []compose.Service{
		{Name: "app", Image: "app:latest", Volumes: []string{"/etc:/etc:ro"}},
	})
	r := Analyze(c)
	for _, f := range r.Findings {
		if f.RuleID == "override_sensitive_volume" {
			t.Fatal("read-only mount should not be flagged")
		}
	}
}
