package nsenter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name string, opts func(*compose.Service)) compose.Service {
	s := compose.Service{Name: name}
	if opts != nil {
		opts(&s)
	}
	return s
}

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestPidHostDetection(t *testing.T) {
	c := collected(svc("agent", func(s *compose.Service) { s.PidMode = "host" }))
	r := Analyze(c)
	if r.Summary.PidHostRisks != 1 {
		t.Fatalf("expected 1 pid host risk, got %d", r.Summary.PidHostRisks)
	}
}

func TestNetworkHostDetection(t *testing.T) {
	c := collected(svc("proxy", func(s *compose.Service) { s.NetworkMode = "host" }))
	r := Analyze(c)
	if r.Summary.HostNamespaceShares != 1 {
		t.Fatalf("expected 1 host namespace share, got %d", r.Summary.HostNamespaceShares)
	}
}

func TestIpcHostDetection(t *testing.T) {
	c := collected(svc("worker", func(s *compose.Service) { s.IpcMode = "host" }))
	r := Analyze(c)
	if r.Summary.HostNamespaceShares != 1 {
		t.Fatalf("expected 1 host namespace share, got %d", r.Summary.HostNamespaceShares)
	}
}

func TestPrivilegedNsenter(t *testing.T) {
	c := collected(svc("debug", func(s *compose.Service) { s.Privileged = true }))
	r := Analyze(c)
	if r.Summary.PrivilegedNsenter != 1 {
		t.Fatalf("expected 1 privileged nsenter, got %d", r.Summary.PrivilegedNsenter)
	}
}

func TestSysAdminCapability(t *testing.T) {
	c := collected(svc("admin", func(s *compose.Service) { s.CapAdd = []string{"SYS_ADMIN"} }))
	r := Analyze(c)
	if r.Summary.SysAdminCaps != 1 {
		t.Fatalf("expected 1 sys_admin cap, got %d", r.Summary.SysAdminCaps)
	}
}

func TestSysPtraceCapability(t *testing.T) {
	c := collected(svc("tracer", func(s *compose.Service) { s.CapAdd = []string{"SYS_PTRACE"} }))
	r := Analyze(c)
	if r.Summary.SysAdminCaps != 1 {
		t.Fatalf("expected 1 ptrace cap, got %d", r.Summary.SysAdminCaps)
	}
}

func TestFullNsenterCombo(t *testing.T) {
	c := collected(svc("escape", func(s *compose.Service) {
		s.PidMode = "host"
		s.Privileged = true
	}))
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "full_nsenter_combo" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected full_nsenter_combo finding")
	}
}

func TestNoFindings(t *testing.T) {
	c := collected(svc("safe", nil))
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestMultipleServices(t *testing.T) {
	c := collected(
		svc("a", func(s *compose.Service) { s.PidMode = "host" }),
		svc("b", func(s *compose.Service) { s.Privileged = true }),
	)
	r := Analyze(c)
	if len(r.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(r.Services))
	}
	if r.Summary.TotalFindings < 2 {
		t.Fatalf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := collected(svc("agent", func(s *compose.Service) { s.PidMode = "host" }))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Namespace Escape") {
		t.Fatal("expected header")
	}
	if !strings.Contains(text, "pid") || !strings.Contains(text, "critical") {
		t.Fatal("expected finding details")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := collected(svc("safe", nil))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "0 findings") {
		t.Fatal("expected 0 findings in output")
	}
}

func TestFormatJSONValid(t *testing.T) {
	c := collected(svc("agent", func(s *compose.Service) { s.Privileged = true }))
	r := Analyze(c)
	out := FormatJSON(r)
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := data["services"]; !ok {
		t.Fatal("expected services key")
	}
}

func TestCapCaseInsensitive(t *testing.T) {
	c := collected(svc("agent", func(s *compose.Service) { s.CapAdd = []string{"sys_admin"} }))
	r := Analyze(c)
	if r.Summary.SysAdminCaps != 1 {
		t.Fatalf("expected case-insensitive cap detection, got %d", r.Summary.SysAdminCaps)
	}
}
