package ptraceprotect

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestPtraceCapAdded(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:   "agent",
		CapAdd: []string{"SYS_PTRACE"},
	})
	r := Analyze(c)
	if r.Summary.PtraceEnabled == 0 {
		t.Fatal("expected ptrace enabled finding")
	}
}

func TestPtracePrivileged(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:       "agent",
		CapAdd:     []string{"SYS_PTRACE"},
		Privileged: true,
	})
	r := Analyze(c)
	if r.Summary.PtracePrivileged == 0 {
		t.Fatal("expected ptrace privileged finding")
	}
}

func TestPtraceHostPid(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		CapAdd:  []string{"SYS_PTRACE"},
		PidMode: "host",
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "ptrace_host_pid" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected ptrace_host_pid finding")
	}
}

func TestPtraceSysAdmin(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:   "agent",
		CapAdd: []string{"SYS_PTRACE", "SYS_ADMIN"},
	})
	r := Analyze(c)
	if r.Summary.DebugCapAdded == 0 {
		t.Fatal("expected debug cap finding")
	}
}

func TestSeccompDisabled(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "agent",
		SecurityOpt: []string{"seccomp=unconfined"},
	})
	r := Analyze(c)
	if r.Summary.SeccompDisabled == 0 {
		t.Fatal("expected seccomp disabled finding")
	}
}

func TestApparmorDisabled(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "agent",
		SecurityOpt: []string{"apparmor=unconfined"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "ptrace_apparmor_off" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected apparmor disabled finding")
	}
}

func TestProcMount(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Volumes: []string{"/proc:/proc"},
	})
	r := Analyze(c)
	if r.Summary.ProcessInspection == 0 {
		t.Fatal("expected proc mount finding")
	}
}

func TestNoFindings(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "safe",
	})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestMultipleServices(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", CapAdd: []string{"SYS_PTRACE"}},
		compose.Service{Name: "b", CapAdd: []string{"SYS_PTRACE"}},
	)
	r := Analyze(c)
	if r.Summary.PtraceEnabled != 2 {
		t.Fatalf("expected 2 ptrace enabled, got %d", r.Summary.PtraceEnabled)
	}
}

func TestCaseInsensitiveCap(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:   "agent",
		CapAdd: []string{"sys_ptrace"},
	})
	r := Analyze(c)
	if r.Summary.PtraceEnabled == 0 {
		t.Fatal("expected case-insensitive cap match")
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:   "agent",
		CapAdd: []string{"SYS_PTRACE"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Ptrace Protection") {
		t.Fatal("expected header in text output")
	}
	if !strings.Contains(text, "agent") {
		t.Fatal("expected service name in output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Findings:           0") {
		t.Fatal("expected 0 findings in text")
	}
}

func TestSummarize(t *testing.T) {
	services := []ServiceResult{
		{Findings: []Finding{{Rule: "ptrace_cap_added"}, {Rule: "ptrace_seccomp_off"}}},
		{Findings: []Finding{{Rule: "ptrace_privileged"}}},
	}
	s := summarize(services)
	if s.TotalFindings != 3 {
		t.Fatalf("expected 3 findings, got %d", s.TotalFindings)
	}
	if s.PtraceEnabled != 1 {
		t.Fatalf("expected 1 ptrace enabled, got %d", s.PtraceEnabled)
	}
}

func TestHasCapability(t *testing.T) {
	if !hasCapability([]string{"SYS_PTRACE", "NET_RAW"}, "SYS_PTRACE") {
		t.Fatal("expected match")
	}
	if hasCapability([]string{"NET_RAW"}, "SYS_PTRACE") {
		t.Fatal("expected no match")
	}
}

func TestSeccompColonFormat(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "agent",
		SecurityOpt: []string{"seccomp:unconfined"},
	})
	r := Analyze(c)
	if r.Summary.SeccompDisabled == 0 {
		t.Fatal("expected seccomp colon format match")
	}
}
