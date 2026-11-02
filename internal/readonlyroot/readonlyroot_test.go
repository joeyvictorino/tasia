package readonlyroot

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestAnalyze_ReadOnlyNoFindings(t *testing.T) {
	c := makeCollected(compose.Service{Name: "safe", ReadOnly: true, Privileged: true})
	r := Analyze(c)

	if r.Summary.TotalFindings != 0 {
		t.Fatalf("read-only service should have 0 findings, got %d", r.Summary.TotalFindings)
	}
	if r.Summary.WritableRoot != 0 {
		t.Errorf("expected 0 writable root, got %d", r.Summary.WritableRoot)
	}
}

func TestAnalyze_WritablePrivileged(t *testing.T) {
	c := makeCollected(compose.Service{Name: "danger", Privileged: true})
	r := Analyze(c)

	if r.Summary.WritablePrivileged != 1 {
		t.Fatalf("expected 1 writable+privileged, got %d", r.Summary.WritablePrivileged)
	}
	f := r.Services[0].Findings[0]
	if f.RuleID != "roroot_writable_privileged" {
		t.Errorf("expected roroot_writable_privileged, got %s", f.RuleID)
	}
	if f.Severity != "critical" {
		t.Errorf("expected critical, got %s", f.Severity)
	}
}

func TestAnalyze_WritableHostNetwork(t *testing.T) {
	c := makeCollected(compose.Service{Name: "net", NetworkMode: "host"})
	r := Analyze(c)

	if r.Summary.WritableHostNetwork != 1 {
		t.Fatalf("expected 1 writable+host_network, got %d", r.Summary.WritableHostNetwork)
	}
	f := r.Services[0].Findings[0]
	if f.RuleID != "roroot_writable_host_network" {
		t.Errorf("expected roroot_writable_host_network, got %s", f.RuleID)
	}
}

func TestAnalyze_WritableDangerousCap(t *testing.T) {
	c := makeCollected(compose.Service{Name: "caps", CapAdd: []string{"SYS_ADMIN"}})
	r := Analyze(c)

	if r.Summary.WritableDangerousCap != 1 {
		t.Fatalf("expected 1 writable+dangerous_cap, got %d", r.Summary.WritableDangerousCap)
	}
	f := r.Services[0].Findings[0]
	if f.RuleID != "roroot_writable_dangerous_cap" {
		t.Errorf("expected roroot_writable_dangerous_cap, got %s", f.RuleID)
	}
}

func TestAnalyze_WritableCapAll(t *testing.T) {
	c := makeCollected(compose.Service{Name: "all", CapAdd: []string{"ALL"}})
	r := Analyze(c)

	if r.Summary.WritableDangerousCap != 1 {
		t.Fatalf("expected 1 for cap ALL, got %d", r.Summary.WritableDangerousCap)
	}
}

func TestAnalyze_WritableDevices(t *testing.T) {
	c := makeCollected(compose.Service{Name: "gpu", Devices: []string{"/dev/nvidia0:/dev/nvidia0"}})
	r := Analyze(c)

	if r.Summary.WritableDevices != 1 {
		t.Fatalf("expected 1 writable+devices, got %d", r.Summary.WritableDevices)
	}
}

func TestAnalyze_CompoundMultiple(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "mega",
		Privileged:  true,
		NetworkMode: "host",
		CapAdd:      []string{"SYS_PTRACE"},
		Devices:     []string{"/dev/fuse:/dev/fuse"},
	})
	r := Analyze(c)

	if r.Summary.TotalFindings != 4 {
		t.Fatalf("expected 4 compound findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyze_SafeCapNotFlagged(t *testing.T) {
	c := makeCollected(compose.Service{Name: "ok", CapAdd: []string{"CHOWN"}})
	r := Analyze(c)

	if r.Summary.WritableDangerousCap != 0 {
		t.Fatalf("CHOWN should not be flagged, got %d", r.Summary.WritableDangerousCap)
	}
}

func TestAnalyze_NoFindingsCleanService(t *testing.T) {
	c := makeCollected(compose.Service{Name: "clean"})
	r := Analyze(c)

	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
	if r.Summary.WritableRoot != 1 {
		t.Errorf("expected 1 writable root, got %d", r.Summary.WritableRoot)
	}
}

func TestAnalyze_MultipleServices(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", Privileged: true},
		compose.Service{Name: "b", ReadOnly: true},
		compose.Service{Name: "c", NetworkMode: "host"},
	)
	r := Analyze(c)

	if r.Summary.TotalServices != 3 {
		t.Fatalf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings != 2 {
		t.Fatalf("expected 2 findings, got %d", r.Summary.TotalFindings)
	}
	if r.Summary.WritableRoot != 2 {
		t.Errorf("expected 2 writable, got %d", r.Summary.WritableRoot)
	}
}

func TestFormatText(t *testing.T) {
	r := Report{
		Services: []ServiceResult{
			{
				Name: "app",
				File: "docker-compose.yml",
				Findings: []Finding{
					{
						Service:     "app",
						File:        "docker-compose.yml",
						RuleID:      "roroot_writable_privileged",
						Severity:    "critical",
						Detail:      "Writable root filesystem with privileged mode",
						Remediation: "Add read_only: true",
					},
				},
			},
		},
		Summary: Summary{
			TotalServices:      1,
			WritableRoot:       1,
			WritablePrivileged: 1,
			TotalFindings:      1,
		},
	}

	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty output")
	}
	if !contains(text, "Writable root filesystem") {
		t.Error("expected writable root count in output")
	}
	if !contains(text, "roroot_writable_privileged") {
		t.Error("expected rule ID in output")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
