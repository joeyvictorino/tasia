package stdinopen

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

func TestStdinTtyCombo(t *testing.T) {
	c := mkCollected(compose.Service{Name: "debug", StdinOpen: true, Tty: true})
	r := Analyze(c)
	if !findRule(r.Services, "stdin_tty_combo") {
		t.Error("expected stdin_tty_combo for stdin_open+tty")
	}
}

func TestStdinOpenOnly(t *testing.T) {
	c := mkCollected(compose.Service{Name: "pipe", StdinOpen: true})
	r := Analyze(c)
	if !findRule(r.Services, "stdin_open_enabled") {
		t.Error("expected stdin_open_enabled")
	}
}

func TestTtyWithoutStdin(t *testing.T) {
	c := mkCollected(compose.Service{Name: "log", Tty: true})
	r := Analyze(c)
	if !findRule(r.Services, "tty_without_stdin") {
		t.Error("expected tty_without_stdin")
	}
}

func TestNoStdinNoTty(t *testing.T) {
	c := mkCollected(compose.Service{Name: "worker"})
	r := Analyze(c)
	if countFindings(r.Services) != 0 {
		t.Error("expected no findings for service without stdin/tty")
	}
}

func TestStdinPrivileged(t *testing.T) {
	c := mkCollected(compose.Service{Name: "root", StdinOpen: true, Privileged: true})
	r := Analyze(c)
	if !findRule(r.Services, "stdin_privileged") {
		t.Error("expected stdin_privileged")
	}
}

func TestStdinPrivilegedLevel(t *testing.T) {
	c := mkCollected(compose.Service{Name: "root", StdinOpen: true, Privileged: true})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "stdin_privileged" && f.Level != "critical" {
				t.Errorf("expected critical level, got %s", f.Level)
			}
		}
	}
}

func TestStdinNetworkHost(t *testing.T) {
	c := mkCollected(compose.Service{Name: "net", StdinOpen: true, NetworkMode: "host"})
	r := Analyze(c)
	if !findRule(r.Services, "stdin_network_host") {
		t.Error("expected stdin_network_host")
	}
}

func TestStdinNoUser(t *testing.T) {
	c := mkCollected(compose.Service{Name: "app", StdinOpen: true})
	r := Analyze(c)
	if !findRule(r.Services, "stdin_no_user") {
		t.Error("expected stdin_no_user when no user set")
	}
}

func TestStdinWithUserNoWarning(t *testing.T) {
	c := mkCollected(compose.Service{Name: "app", StdinOpen: true, User: "1000:1000"})
	r := Analyze(c)
	if findRule(r.Services, "stdin_no_user") {
		t.Error("should not flag stdin_no_user when user is set")
	}
}

func TestStdinWritableVolume(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:      "mount",
		StdinOpen: true,
		Volumes:   []string{"/host/data:/data"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "stdin_writable_volume") {
		t.Error("expected stdin_writable_volume")
	}
}

func TestStdinReadOnlyVolume(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:      "safe",
		StdinOpen: true,
		Volumes:   []string{"/host/data:/data:ro"},
	})
	r := Analyze(c)
	if findRule(r.Services, "stdin_writable_volume") {
		t.Error("should not flag read-only volume")
	}
}

func TestTtyWritableVolume(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "tty-mount",
		Tty:     true,
		Volumes: []string{"/host:/mnt"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "stdin_writable_volume") {
		t.Error("expected stdin_writable_volume for tty with writable volume")
	}
}

func TestStdinExtraCaps(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:      "cap",
		StdinOpen: true,
		CapAdd:    []string{"SYS_ADMIN"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "stdin_extra_caps") {
		t.Error("expected stdin_extra_caps")
	}
}

func TestNoCapNoWarning(t *testing.T) {
	c := mkCollected(compose.Service{Name: "plain", StdinOpen: true, User: "app"})
	r := Analyze(c)
	if findRule(r.Services, "stdin_extra_caps") {
		t.Error("should not flag extra caps when none added")
	}
}

func TestMultipleServices(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "a", StdinOpen: true, Tty: true},
		compose.Service{Name: "b"},
		compose.Service{Name: "c", Tty: true},
	)
	r := Analyze(c)
	if len(r.Services) != 3 {
		t.Errorf("expected 3 services, got %d", len(r.Services))
	}
	if r.Summary.TotalFindings == 0 {
		t.Error("expected some findings")
	}
}

func TestSummaryTotals(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "a", StdinOpen: true, Tty: true},
		compose.Service{Name: "b", StdinOpen: true, Privileged: true},
	)
	r := Analyze(c)
	if r.Summary.StdinTtyCombo != 1 {
		t.Errorf("expected 1 stdin_tty_combo, got %d", r.Summary.StdinTtyCombo)
	}
	if r.Summary.PrivilegedStdin != 1 {
		t.Errorf("expected 1 privileged_stdin, got %d", r.Summary.PrivilegedStdin)
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	c := mkCollected(compose.Service{Name: "test", StdinOpen: true, Tty: true})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Stdin/TTY Security Audit") {
		t.Error("expected header in text output")
	}
}

func TestFormatTextContainsService(t *testing.T) {
	c := mkCollected(compose.Service{Name: "myapp", StdinOpen: true})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "myapp") {
		t.Error("expected service name in text output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "clean"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "no findings") {
		t.Error("expected 'no findings' message")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if len(r.Services) != 0 {
		t.Error("expected no services")
	}
	if r.Summary.TotalFindings != 0 {
		t.Error("expected zero findings")
	}
}

func TestStdinComboDoesNotDuplicateEnabled(t *testing.T) {
	c := mkCollected(compose.Service{Name: "both", StdinOpen: true, Tty: true, User: "app"})
	r := Analyze(c)
	if findRule(r.Services, "stdin_open_enabled") {
		t.Error("stdin_tty_combo should suppress stdin_open_enabled")
	}
}

func TestNetworkHostWithoutStdin(t *testing.T) {
	c := mkCollected(compose.Service{Name: "net", NetworkMode: "host"})
	r := Analyze(c)
	if findRule(r.Services, "stdin_network_host") {
		t.Error("should not flag network_host without stdin_open")
	}
}

func TestPrivilegedWithoutStdin(t *testing.T) {
	c := mkCollected(compose.Service{Name: "priv", Privileged: true})
	r := Analyze(c)
	if findRule(r.Services, "stdin_privileged") {
		t.Error("should not flag privileged without stdin_open")
	}
}
