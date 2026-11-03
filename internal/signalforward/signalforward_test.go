package signalforward

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

func countRule(results []ServiceResult, rule string) int {
	n := 0
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				n++
			}
		}
	}
	return n
}

func TestNoInitProcess(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if !findRule(r.Services, "signal_no_init") {
		t.Error("expected signal_no_init when init is false")
	}
}

func TestInitProcessSafe(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Init: true})
	r := Analyze(c)
	if findRule(r.Services, "signal_no_init") {
		t.Error("should not flag service with init: true")
	}
}

func TestTtySkipsNoInit(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Tty: true})
	r := Analyze(c)
	if findRule(r.Services, "signal_no_init") {
		t.Error("should not flag signal_no_init for TTY service (handled by tty_without_init)")
	}
}

func TestShellEntrypoint(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "worker",
		Entrypoint: []string{"/bin/sh", "-c", "python app.py"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "signal_shell_entrypoint") {
		t.Error("expected signal_shell_entrypoint for sh -c entrypoint")
	}
}

func TestBashEntrypoint(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Command: []string{"bash", "-c", "node server.js"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "signal_shell_entrypoint") {
		t.Error("expected signal_shell_entrypoint for bash -c command")
	}
}

func TestExecFormEntrypoint(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "worker",
		Entrypoint: []string{"python", "app.py"},
	})
	r := Analyze(c)
	if findRule(r.Services, "signal_shell_entrypoint") {
		t.Error("should not flag exec-form entrypoint")
	}
}

func TestSigkillStopSignal(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "api",
		StopSignal: "SIGKILL",
	})
	r := Analyze(c)
	if !findRule(r.Services, "signal_no_stop_signal") {
		t.Error("expected signal_no_stop_signal for SIGKILL")
	}
}

func TestNumericKillSignal(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "api",
		StopSignal: "9",
	})
	r := Analyze(c)
	if !findRule(r.Services, "signal_no_stop_signal") {
		t.Error("expected signal_no_stop_signal for signal 9")
	}
}

func TestSigtermStopSignal(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "api",
		StopSignal: "SIGTERM",
	})
	r := Analyze(c)
	if findRule(r.Services, "signal_no_stop_signal") {
		t.Error("should not flag SIGTERM stop signal")
	}
}

func TestZeroGracePeriod(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:            "fast",
		StopGracePeriod: "0s",
	})
	r := Analyze(c)
	if !findRule(r.Services, "signal_short_grace") {
		t.Error("expected signal_short_grace for 0s grace period")
	}
}

func TestVeryShortGracePeriod(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:            "fast",
		StopGracePeriod: "1s",
	})
	r := Analyze(c)
	if !findRule(r.Services, "signal_short_grace") {
		t.Error("expected signal_short_grace for 1s grace period")
	}
}

func TestNormalGracePeriod(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:            "api",
		StopGracePeriod: "30s",
	})
	r := Analyze(c)
	if findRule(r.Services, "signal_short_grace") {
		t.Error("should not flag 30s grace period")
	}
}

func TestTtyWithoutInit(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "dev",
		Tty:  true,
	})
	r := Analyze(c)
	if !findRule(r.Services, "signal_tty_without_init") {
		t.Error("expected signal_tty_without_init for TTY service without init")
	}
}

func TestTtyWithInit(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "dev",
		Tty:  true,
		Init: true,
	})
	r := Analyze(c)
	if findRule(r.Services, "signal_tty_without_init") {
		t.Error("should not flag TTY service with init")
	}
}

func TestNoTrapHandler(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Command: []string{"sh", "-c", "python app.py"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "signal_no_trap_handler") {
		t.Error("expected signal_no_trap_handler for shell without trap")
	}
}

func TestTrapHandlerPresent(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Command: []string{"sh", "-c", "trap 'kill $PID' TERM; python app.py & PID=$!; wait"},
	})
	r := Analyze(c)
	if findRule(r.Services, "signal_no_trap_handler") {
		t.Error("should not flag shell with trap handler")
	}
}

func TestSummaryCount(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "a", StopSignal: "SIGKILL"},
		compose.Service{Name: "b", StopGracePeriod: "0s"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Signal Forwarding") {
		t.Error("expected header in text output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "safe", Init: true})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "(no findings)") {
		t.Error("expected no findings message")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestMultipleFindings(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:            "risky",
		Entrypoint:      []string{"sh", "-c", "python app.py"},
		StopSignal:      "SIGKILL",
		StopGracePeriod: "0s",
		Tty:             true,
	})
	r := Analyze(c)
	if r.Summary.TotalFindings < 4 {
		t.Errorf("expected at least 4 findings, got %d", r.Summary.TotalFindings)
	}
}
