package ipcns

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) collect.Collected {
	return collect.Collected{
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: services}},
	}
}

func TestNoServices(t *testing.T) {
	r := Analyze(collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0, got %d", r.Summary.TotalServices)
	}
}

func TestCleanService(t *testing.T) {
	c := makeCollected(compose.Service{Name: "app", Image: "myapp:latest"})
	r := Analyze(c)
	if r.Services[0].Score != 100 {
		t.Errorf("expected score 100, got %d", r.Services[0].Score)
	}
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(r.Services[0].Findings))
	}
}

func TestIpcHostMode(t *testing.T) {
	c := makeCollected(compose.Service{Name: "app", IpcMode: "host"})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "ipc_host_mode" {
			found = true
			if f.Severity != "high" {
				t.Errorf("expected high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected ipc_host_mode finding")
	}
	if r.Summary.WithIpcHost != 1 {
		t.Errorf("expected 1 ipc host, got %d", r.Summary.WithIpcHost)
	}
}

func TestPrivilegedIpcHost(t *testing.T) {
	c := makeCollected(compose.Service{Name: "app", IpcMode: "host", Privileged: true})
	r := Analyze(c)
	categories := map[string]bool{}
	for _, f := range r.Services[0].Findings {
		categories[f.Category] = true
	}
	if !categories["privileged_ipc_host"] {
		t.Error("expected privileged_ipc_host finding")
	}
}

func TestIpcSharedContainer(t *testing.T) {
	c := makeCollected(compose.Service{Name: "sidecar", IpcMode: "container:redis"})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "ipc_shared_container" {
			found = true
			if f.Severity != "medium" {
				t.Errorf("expected medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected ipc_shared_container finding")
	}
	if r.Summary.WithIpcShared != 1 {
		t.Errorf("expected 1 shared, got %d", r.Summary.WithIpcShared)
	}
}

func TestIpcHostWithShm(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "app",
		IpcMode: "host",
		Volumes: []string{"/dev/shm:/dev/shm"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "ipc_host_with_shm" {
			found = true
		}
	}
	if !found {
		t.Error("expected ipc_host_with_shm finding")
	}
}

func TestSummaryTotals(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", IpcMode: "host"},
		compose.Service{Name: "b", IpcMode: "container:a"},
		compose.Service{Name: "c", Image: "clean:latest"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithIpcHost != 1 {
		t.Errorf("expected 1 ipc host, got %d", r.Summary.WithIpcHost)
	}
	if r.Summary.WithIpcShared != 1 {
		t.Errorf("expected 1 shared, got %d", r.Summary.WithIpcShared)
	}
	if r.Summary.WithDefault != 1 {
		t.Errorf("expected 1 default, got %d", r.Summary.WithDefault)
	}
}

func TestScoreGrading(t *testing.T) {
	tests := []struct {
		score int
		grade string
	}{
		{100, "A"}, {90, "A"}, {85, "B"}, {75, "C"}, {65, "D"}, {50, "F"},
	}
	for _, tt := range tests {
		got := scoreToGrade(tt.score)
		if got != tt.grade {
			t.Errorf("scoreToGrade(%d) = %s, want %s", tt.score, got, tt.grade)
		}
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := makeCollected(compose.Service{Name: "app", IpcMode: "host"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "IPC Namespace Audit") {
		t.Error("expected header")
	}
	if !strings.Contains(text, "ipc_host_mode") {
		t.Error("expected finding in output")
	}
}

func TestScoreFloor(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:       "bad",
		IpcMode:    "host",
		Privileged: true,
		Volumes:    []string{"/dev/shm:/dev/shm"},
	})
	r := Analyze(c)
	if r.Services[0].Score < 0 {
		t.Error("score should not go below 0")
	}
}
