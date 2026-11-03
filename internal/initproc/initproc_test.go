package initproc

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	cf := compose.File{Path: "docker-compose.yml", Services: services}
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{cf}}
}

func findRule(results []ServiceResult, rule string) bool {
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return true
			}
		}
	}
	return false
}

func countFindings(results []ServiceResult) int {
	n := 0
	for _, sr := range results {
		n += len(sr.Findings)
	}
	return n
}

func TestMissingInit(t *testing.T) {
	c := mkCollected(compose.Service{Name: "worker"})
	r := Analyze(c)
	if !findRule(r.Services, "missing_init") {
		t.Error("expected missing_init for service without init:true")
	}
}

func TestInitEnabled(t *testing.T) {
	c := mkCollected(compose.Service{Name: "worker", Init: true})
	r := Analyze(c)
	if findRule(r.Services, "missing_init") {
		t.Error("should not flag missing_init when init:true")
	}
}

func TestPidHostNoInit(t *testing.T) {
	c := mkCollected(compose.Service{Name: "host", PidMode: "host"})
	r := Analyze(c)
	if !findRule(r.Services, "pid_host_no_init") {
		t.Error("expected pid_host_no_init")
	}
	if findRule(r.Services, "missing_init") {
		t.Error("should not flag missing_init for pid:host")
	}
}

func TestPidHostWithInit(t *testing.T) {
	c := mkCollected(compose.Service{Name: "host", PidMode: "host", Init: true})
	r := Analyze(c)
	if findRule(r.Services, "pid_host_no_init") {
		t.Error("should not flag pid_host_no_init when init is true")
	}
}

func TestInitPrivileged(t *testing.T) {
	c := mkCollected(compose.Service{Name: "priv", Init: true, Privileged: true})
	r := Analyze(c)
	if !findRule(r.Services, "init_privileged") {
		t.Error("expected init_privileged")
	}
}

func TestInitPrivilegedLevel(t *testing.T) {
	c := mkCollected(compose.Service{Name: "priv", Init: true, Privileged: true})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "init_privileged" && f.Level != "high" {
				t.Errorf("expected high level, got %s", f.Level)
			}
		}
	}
}

func TestInitNotPrivileged(t *testing.T) {
	c := mkCollected(compose.Service{Name: "safe", Init: true})
	r := Analyze(c)
	if findRule(r.Services, "init_privileged") {
		t.Error("should not flag init_privileged when not privileged")
	}
}

func TestInitOomDisabled(t *testing.T) {
	c := mkCollected(compose.Service{Name: "oom", Init: true, OomKillDisable: true})
	r := Analyze(c)
	if !findRule(r.Services, "init_oom_disabled") {
		t.Error("expected init_oom_disabled")
	}
}

func TestInitOomEnabled(t *testing.T) {
	c := mkCollected(compose.Service{Name: "ok", Init: true})
	r := Analyze(c)
	if findRule(r.Services, "init_oom_disabled") {
		t.Error("should not flag when OOM kill is not disabled")
	}
}

func TestCustomStopNoInit(t *testing.T) {
	c := mkCollected(compose.Service{Name: "sig", StopSignal: "SIGQUIT"})
	r := Analyze(c)
	if !findRule(r.Services, "custom_stop_no_init") {
		t.Error("expected custom_stop_no_init")
	}
}

func TestCustomStopWithInit(t *testing.T) {
	c := mkCollected(compose.Service{Name: "sig", Init: true, StopSignal: "SIGQUIT"})
	r := Analyze(c)
	if findRule(r.Services, "custom_stop_no_init") {
		t.Error("should not flag custom_stop when init is true")
	}
}

func TestDefaultStopSignal(t *testing.T) {
	c := mkCollected(compose.Service{Name: "def", StopSignal: "SIGTERM"})
	r := Analyze(c)
	if findRule(r.Services, "custom_stop_no_init") {
		t.Error("should not flag default SIGTERM")
	}
}

func TestNoInitNoGrace(t *testing.T) {
	c := mkCollected(compose.Service{Name: "fast"})
	r := Analyze(c)
	if !findRule(r.Services, "no_init_no_grace") {
		t.Error("expected no_init_no_grace")
	}
}

func TestNoInitWithGrace(t *testing.T) {
	c := mkCollected(compose.Service{Name: "grace", StopGracePeriod: "30s"})
	r := Analyze(c)
	if findRule(r.Services, "no_init_no_grace") {
		t.Error("should not flag when grace period is set")
	}
}

func TestInitShellEntrypoint(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "shell",
		Init:       true,
		Entrypoint: []string{"cd /app && ./start.sh"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "init_shell_entrypoint") {
		t.Error("expected init_shell_entrypoint for shell-form entrypoint")
	}
}

func TestInitExecEntrypoint(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "exec",
		Init:       true,
		Entrypoint: []string{"/app/start"},
	})
	r := Analyze(c)
	if findRule(r.Services, "init_shell_entrypoint") {
		t.Error("should not flag exec-form entrypoint")
	}
}

func TestInitShellCommand(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "cmd",
		Init:    true,
		Command: []string{"sleep 10 && echo done"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "init_shell_entrypoint") {
		t.Error("expected init_shell_entrypoint for shell-form command")
	}
}

func TestMultipleServices(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "a"},
		compose.Service{Name: "b", Init: true},
		compose.Service{Name: "c", Init: true, Privileged: true},
	)
	r := Analyze(c)
	if len(r.Services) != 3 {
		t.Errorf("expected 3 services, got %d", len(r.Services))
	}
}

func TestSummaryMissingInit(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "a"},
		compose.Service{Name: "b"},
	)
	r := Analyze(c)
	if r.Summary.MissingInit != 2 {
		t.Errorf("expected 2 missing_init, got %d", r.Summary.MissingInit)
	}
}

func TestFormatTextHeader(t *testing.T) {
	c := mkCollected(compose.Service{Name: "test"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Init Process Security Audit") {
		t.Error("expected header in text output")
	}
}

func TestFormatTextServiceName(t *testing.T) {
	c := mkCollected(compose.Service{Name: "myservice", Init: true})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "myservice") {
		t.Error("expected service name in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "clean", Init: true, StopGracePeriod: "10s"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "no findings") {
		t.Error("expected 'no findings' for clean service")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if len(r.Services) != 0 {
		t.Error("expected no services")
	}
}
