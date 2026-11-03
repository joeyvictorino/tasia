package gracefulshutdown

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root:         "/test",
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}},
	}
}

func TestNoInit(t *testing.T) {
	svc := compose.Service{Name: "web"}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "shutdown_no_init" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected shutdown_no_init finding")
	}
}

func TestWithInit(t *testing.T) {
	svc := compose.Service{Name: "web", Init: true}
	r := Analyze(collected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "shutdown_no_init" {
				t.Error("should not flag no_init when init: true")
			}
		}
	}
}

func TestBadStopSignalKill(t *testing.T) {
	svc := compose.Service{Name: "worker", StopSignal: "SIGKILL", Init: true}
	r := Analyze(collected(svc))
	if r.Summary.BadStopSignal == 0 {
		t.Error("expected bad stop signal finding for SIGKILL")
	}
}

func TestBadStopSignalNumber(t *testing.T) {
	svc := compose.Service{Name: "worker", StopSignal: "9", Init: true}
	r := Analyze(collected(svc))
	if r.Summary.BadStopSignal == 0 {
		t.Error("expected bad stop signal finding for signal 9")
	}
}

func TestGoodStopSignal(t *testing.T) {
	svc := compose.Service{Name: "worker", StopSignal: "SIGTERM", Init: true}
	r := Analyze(collected(svc))
	if r.Summary.BadStopSignal != 0 {
		t.Error("SIGTERM should not be flagged as bad")
	}
}

func TestGraceTooShort(t *testing.T) {
	svc := compose.Service{Name: "api", StopGracePeriod: "2s", Init: true}
	r := Analyze(collected(svc))
	if r.Summary.GraceTooShort == 0 {
		t.Error("expected grace too short for 2s")
	}
}

func TestGraceOk(t *testing.T) {
	svc := compose.Service{Name: "api", StopGracePeriod: "30s", Init: true}
	r := Analyze(collected(svc))
	if r.Summary.GraceTooShort != 0 {
		t.Error("30s should not be flagged as too short")
	}
	if r.Summary.GraceTooLong != 0 {
		t.Error("30s should not be flagged as too long")
	}
}

func TestGraceTooLong(t *testing.T) {
	svc := compose.Service{Name: "api", StopGracePeriod: "10m", Init: true}
	r := Analyze(collected(svc))
	if r.Summary.GraceTooLong == 0 {
		t.Error("expected grace too long for 10m")
	}
}

func TestMissingGrace(t *testing.T) {
	svc := compose.Service{Name: "app", Init: true}
	r := Analyze(collected(svc))
	if r.Summary.MissingGrace == 0 {
		t.Error("expected missing grace period finding")
	}
}

func TestPrivilegedNoInit(t *testing.T) {
	svc := compose.Service{Name: "agent", Privileged: true}
	r := Analyze(collected(svc))
	if r.Summary.PrivilegedNoInit == 0 {
		t.Error("expected privileged no init finding")
	}
}

func TestPrivilegedWithInit(t *testing.T) {
	svc := compose.Service{Name: "agent", Privileged: true, Init: true}
	r := Analyze(collected(svc))
	if r.Summary.PrivilegedNoInit != 0 {
		t.Error("privileged with init should not flag privileged_no_init")
	}
}

func TestMultipleServices(t *testing.T) {
	svc1 := compose.Service{Name: "web"}
	svc2 := compose.Service{Name: "worker", StopSignal: "SIGKILL"}
	r := Analyze(collected(svc1, svc2))
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	svc := compose.Service{Name: "web", StopSignal: "SIGKILL"}
	r := Analyze(collected(svc))
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !containsStr(text, "Graceful Shutdown Audit") {
		t.Error("expected header in output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	svc := compose.Service{Name: "clean", Init: true, StopGracePeriod: "15s"}
	r := Analyze(collected(svc))
	text := FormatText(r)
	if !containsStr(text, "0 findings") {
		t.Error("expected 0 findings in output")
	}
}

func TestParseDurationSeconds(t *testing.T) {
	if parseDuration("30s") != 30 {
		t.Error("expected 30 for 30s")
	}
}

func TestParseDurationMinutes(t *testing.T) {
	if parseDuration("2m") != 120 {
		t.Error("expected 120 for 2m")
	}
}

func TestParseDurationMs(t *testing.T) {
	if parseDuration("500ms") != 0 {
		t.Error("expected 0 for 500ms")
	}
}

func TestStopSignalStop(t *testing.T) {
	svc := compose.Service{Name: "svc", StopSignal: "SIGSTOP", Init: true}
	r := Analyze(collected(svc))
	if r.Summary.BadStopSignal == 0 {
		t.Error("expected bad stop signal for SIGSTOP")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
