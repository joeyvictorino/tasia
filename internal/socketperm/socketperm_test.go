package socketperm

import (
	"encoding/json"
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

func svc(name string, vols ...string) compose.Service {
	return compose.Service{Name: name, Volumes: vols}
}

func TestDockerSocketDetected(t *testing.T) {
	r := Analyze(collected(svc("agent", "/var/run/docker.sock:/var/run/docker.sock")))
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Findings))
	}
	if r.Findings[0].RuleID != "socket_docker_mount" {
		t.Errorf("expected socket_docker_mount, got %s", r.Findings[0].RuleID)
	}
	if r.Findings[0].Severity != "critical" {
		t.Errorf("expected critical, got %s", r.Findings[0].Severity)
	}
}

func TestAlternateDockerSocket(t *testing.T) {
	r := Analyze(collected(svc("svc", "/run/docker.sock:/var/run/docker.sock")))
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "socket_docker_mount" {
		t.Error("expected docker socket detection for /run/docker.sock")
	}
}

func TestContainerdSocketDetected(t *testing.T) {
	r := Analyze(collected(svc("runtime", "/var/run/containerd/containerd.sock:/run/containerd.sock")))
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Findings))
	}
	if r.Findings[0].RuleID != "socket_runtime_mount" {
		t.Errorf("expected socket_runtime_mount, got %s", r.Findings[0].RuleID)
	}
	if r.Findings[0].Severity != "high" {
		t.Errorf("expected high, got %s", r.Findings[0].Severity)
	}
}

func TestCrioSocketDetected(t *testing.T) {
	r := Analyze(collected(svc("cri", "/var/run/crio/crio.sock:/run/crio.sock")))
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "socket_runtime_mount" {
		t.Error("expected runtime socket detection for crio")
	}
}

func TestDBusSocketDetected(t *testing.T) {
	r := Analyze(collected(svc("app", "/var/run/dbus/system_bus_socket:/run/dbus")))
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "socket_sensitive_mount" {
		t.Error("expected sensitive socket detection for dbus")
	}
}

func TestX11SocketDetected(t *testing.T) {
	r := Analyze(collected(svc("gui", "/tmp/.X11-unix:/tmp/.X11-unix")))
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "socket_sensitive_mount" {
		t.Error("expected sensitive socket detection for X11")
	}
}

func TestWritableSocketDetected(t *testing.T) {
	r := Analyze(collected(svc("app", "/opt/myapp/app.sock:/run/app.sock")))
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "socket_writable_mount" {
		t.Error("expected writable socket detection")
	}
}

func TestReadOnlySocketClean(t *testing.T) {
	r := Analyze(collected(svc("app", "/opt/myapp/app.sock:/run/app.sock:ro")))
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 findings for read-only socket, got %d", len(r.Findings))
	}
}

func TestNoSocketsClean(t *testing.T) {
	r := Analyze(collected(svc("web", "/data:/app/data")))
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Findings))
	}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.Total != 0 {
		t.Errorf("expected 0 total, got %d", r.Summary.Total)
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(collected(
		svc("a", "/var/run/docker.sock:/var/run/docker.sock"),
		svc("b", "/var/run/containerd/containerd.sock:/run/c.sock"),
	))
	if len(r.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(r.Findings))
	}
	if r.Summary.Services != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.Services)
	}
}

func TestScorePerfect(t *testing.T) {
	r := Analyze(collected(svc("clean", "/data:/data")))
	if Score(r) != 100 {
		t.Errorf("expected score 100, got %.0f", Score(r))
	}
}

func TestScoreDegrades(t *testing.T) {
	r := Analyze(collected(svc("a", "/var/run/docker.sock:/var/run/docker.sock")))
	s := Score(r)
	if s >= 100 {
		t.Errorf("expected score < 100, got %.0f", s)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(collected(svc("agent", "/var/run/docker.sock:/var/run/docker.sock")))
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text")
	}
	if !contains(text, "Socket Permission") {
		t.Error("expected header in output")
	}
	if !contains(text, "socket_docker_mount") {
		t.Error("expected rule ID in output")
	}
}

func TestFormatTextClean(t *testing.T) {
	r := Analyze(collected(svc("clean", "/data:/data")))
	text := FormatText(r)
	if !contains(text, "No socket") {
		t.Error("expected clean message")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	r := Analyze(collected(svc("agent", "/var/run/docker.sock:/var/run/docker.sock")))
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var r2 Report
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if len(r2.Findings) != 1 {
		t.Errorf("expected 1 finding after round-trip, got %d", len(r2.Findings))
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
