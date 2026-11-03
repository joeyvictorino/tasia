package procexec

import (
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

func svc(name string) compose.Service {
	return compose.Service{Name: name}
}

func TestIsShell(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{"/bin/sh", true},
		{"/bin/bash", true},
		{"bash", true},
		{"sh", true},
		{"/usr/bin/zsh", true},
		{"python", false},
		{"myapp", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isShell(tt.cmd)
		if got != tt.want {
			t.Errorf("isShell(%q) = %v, want %v", tt.cmd, got, tt.want)
		}
	}
}

func TestIsDangerousCommand(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{"curl", true},
		{"wget", true},
		{"python3", true},
		{"gcc", true},
		{"apt-get", true},
		{"myapp", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isDangerousCommand(tt.cmd)
		if got != tt.want {
			t.Errorf("isDangerousCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
		}
	}
}

func TestIsDebugEntrypoint(t *testing.T) {
	tests := []struct {
		ep   string
		want bool
	}{
		{"sleep infinity", true},
		{"tail -f /dev/null", true},
		{"sleep 999", true},
		{"python app.py", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isDebugEntrypoint(tt.ep)
		if got != tt.want {
			t.Errorf("isDebugEntrypoint(%q) = %v, want %v", tt.ep, got, tt.want)
		}
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyzeCleanService(t *testing.T) {
	s := svc("web")
	s.Command = []string{"python", "app.py", "--port", "8080"}
	c := collected(s)
	r := Analyze(c)
	dangerousFound := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "shell_entrypoint" || f.Rule == "shell_command" {
				dangerousFound = true
			}
		}
	}
	if dangerousFound {
		t.Fatal("clean service should not have shell findings")
	}
}

func TestShellEntrypoint(t *testing.T) {
	s := svc("debug")
	s.Entrypoint = []string{"/bin/bash"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "shell_entrypoint" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected shell_entrypoint finding")
	}
}

func TestShellCommand(t *testing.T) {
	s := svc("debug")
	s.Command = []string{"sh"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "shell_command" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected shell_command finding")
	}
}

func TestDebugEntrypoint(t *testing.T) {
	s := svc("agent")
	s.Entrypoint = []string{"sleep", "infinity"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "debug_entrypoint" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected debug_entrypoint finding")
	}
}

func TestDebugCommand(t *testing.T) {
	s := svc("agent")
	s.Command = []string{"tail", "-f", "/dev/null"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "debug_command" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected debug_command finding")
	}
}

func TestDangerousCommandInCmd(t *testing.T) {
	s := svc("build")
	s.Command = []string{"/usr/bin/gcc", "-o", "app", "main.c"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "dangerous_command" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected dangerous_command finding for gcc")
	}
}

func TestPtraceCapability(t *testing.T) {
	s := svc("debugger")
	s.CapAdd = []string{"SYS_PTRACE"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "ptrace_capability" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected ptrace_capability finding")
	}
}

func TestSysAdminCapability(t *testing.T) {
	s := svc("admin")
	s.CapAdd = []string{"SYS_ADMIN"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "sysadmin_capability" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected sysadmin_capability finding")
	}
}

func TestInteractiveMode(t *testing.T) {
	s := svc("shell")
	s.StdinOpen = true
	s.Tty = true
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "interactive_mode" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected interactive_mode finding")
	}
}

func TestStdinOnlyNoFinding(t *testing.T) {
	s := svc("worker")
	s.StdinOpen = true
	s.Tty = false
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "interactive_mode" {
				t.Fatal("stdin_open alone should not trigger interactive_mode")
			}
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	s := svc("debug")
	s.Entrypoint = []string{"/bin/bash"}
	s.CapAdd = []string{"SYS_PTRACE"}
	s.StdinOpen = true
	s.Tty = true
	c := collected(s)
	r := Analyze(c)
	if r.Summary.ShellAccess < 1 {
		t.Fatal("expected shell access count > 0")
	}
	if r.Summary.UnrestrictedExec < 1 {
		t.Fatal("expected unrestricted exec count > 0")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text")
	}
	if !containsStr(text, "0 findings") {
		t.Fatal("expected 0 findings")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	s := svc("debug")
	s.Entrypoint = []string{"sleep", "infinity"}
	c := collected(s)
	r := Analyze(c)
	text := FormatText(r)
	if !containsStr(text, "debug") {
		t.Fatal("expected service name")
	}
	if !containsStr(text, "Process Execution") {
		t.Fatal("expected header")
	}
}

func TestExtractBasename(t *testing.T) {
	tests := []struct {
		path, want string
	}{
		{"/usr/bin/gcc", "gcc"},
		{"curl", "curl"},
		{"/bin/bash", "bash"},
	}
	for _, tt := range tests {
		got := extractBasename(tt.path)
		if got != tt.want {
			t.Errorf("extractBasename(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("shell")
	s1.Command = []string{"bash"}
	s2 := svc("clean")
	s2.Command = []string{"python", "app.py"}
	c := collected(s1, s2)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || findSubstr(s, sub))
}

func findSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
