package sysctls

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyzeNoSysctls(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{
				{Name: "web"},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 1 {
		t.Fatalf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.ServicesWithSysctls != 0 {
		t.Fatalf("expected 0 with sysctls, got %d", r.Summary.ServicesWithSysctls)
	}
}

func TestAnalyzeDangerousIPForward(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{
				{Name: "router", Sysctls: map[string]string{
					"net.ipv4.ip_forward": "1",
				}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
	f := r.Services[0].Findings[0]
	if f.RuleID != "sysctl_dangerous" {
		t.Errorf("expected rule_id sysctl_dangerous, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected severity high, got %s", f.Severity)
	}
	if f.SysctlKey != "net.ipv4.ip_forward" {
		t.Errorf("expected sysctl key net.ipv4.ip_forward, got %s", f.SysctlKey)
	}
}

func TestAnalyzeCriticalCorePattern(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "exploit", Sysctls: map[string]string{
					"kernel.core_pattern": "|/tmp/evil %p",
				}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
	if r.Services[0].Findings[0].Severity != "critical" {
		t.Errorf("expected critical severity, got %s", r.Services[0].Findings[0].Severity)
	}
}

func TestAnalyzeHighSharedMemory(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "db", Sysctls: map[string]string{
					"kernel.shmmax": "274877906944", // 256GB
				}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
	if r.Services[0].Findings[0].SysctlKey != "kernel.shmmax" {
		t.Errorf("expected sysctl key kernel.shmmax, got %s", r.Services[0].Findings[0].SysctlKey)
	}
}

func TestAnalyzeReasonableSharedMemory(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "db", Sysctls: map[string]string{
					"kernel.shmmax": "33554432", // 32MB - reasonable
				}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyzeOvercommitMemory(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "ml", Sysctls: map[string]string{
					"vm.overcommit_memory": "1",
				}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyzeOvercommitMemoryDefault(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "ml", Sysctls: map[string]string{
					"vm.overcommit_memory": "0",
				}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for overcommit_memory=0, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyzeMultipleServices(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "router", Sysctls: map[string]string{
					"net.ipv4.ip_forward":          "1",
					"net.ipv4.conf.all.forwarding": "1",
				}},
				{Name: "safe", Sysctls: map[string]string{
					"net.core.somaxconn": "1024",
				}},
				{Name: "plain"},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Fatalf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.ServicesWithSysctls != 2 {
		t.Fatalf("expected 2 services with sysctls, got %d", r.Summary.ServicesWithSysctls)
	}
	if r.Summary.DangerousSysctls != 2 {
		t.Fatalf("expected 2 dangerous sysctls, got %d", r.Summary.DangerousSysctls)
	}
}

func TestFormatText(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "svc", Sysctls: map[string]string{
					"net.ipv4.ip_forward": "1",
				}},
			}},
		},
	}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text output")
	}
	if !contains(text, "Kernel Sysctl Audit") {
		t.Error("expected header in text output")
	}
	if !contains(text, "net.ipv4.ip_forward") {
		t.Error("expected sysctl key in text output")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
