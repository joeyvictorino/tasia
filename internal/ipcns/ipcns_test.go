package ipcns

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestAnalyzeCleanService(t *testing.T) {
	c := mkCollected(compose.Service{Name: "app"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyzeHostIpc(t *testing.T) {
	c := mkCollected(compose.Service{Name: "svc", IpcMode: "host"})
	r := Analyze(c)
	if r.Summary.HostIpc != 1 {
		t.Errorf("expected 1 host IPC, got %d", r.Summary.HostIpc)
	}
	if r.Services[0].Findings[0].RuleID != "ipcns_host_ipc" {
		t.Errorf("expected ipcns_host_ipc, got %s", r.Services[0].Findings[0].RuleID)
	}
}

func TestAnalyzeSharedIpc(t *testing.T) {
	c := mkCollected(compose.Service{Name: "svc", IpcMode: "service:db"})
	r := Analyze(c)
	if r.Summary.SharedIpc != 1 {
		t.Errorf("expected 1 shared IPC, got %d", r.Summary.SharedIpc)
	}
	if !strings.Contains(r.Services[0].Findings[0].Detail, "db") {
		t.Error("expected target name in detail")
	}
}

func TestAnalyzeLargeShm(t *testing.T) {
	c := mkCollected(compose.Service{Name: "svc", ShmSize: "512mb"})
	r := Analyze(c)
	if r.Summary.LargeShm != 1 {
		t.Errorf("expected 1 large SHM, got %d", r.Summary.LargeShm)
	}
}

func TestAnalyzeSmallShmNoFinding(t *testing.T) {
	c := mkCollected(compose.Service{Name: "svc", ShmSize: "64mb"})
	r := Analyze(c)
	if r.Summary.LargeShm != 0 {
		t.Errorf("expected 0 large SHM, got %d", r.Summary.LargeShm)
	}
}

func TestAnalyzeShmMount(t *testing.T) {
	c := mkCollected(compose.Service{Name: "svc", Volumes: []string{"/dev/shm:/dev/shm"}})
	r := Analyze(c)
	if r.Summary.ShmMount != 1 {
		t.Errorf("expected 1 SHM mount, got %d", r.Summary.ShmMount)
	}
}

func TestAnalyzeMultipleFindings(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "svc", IpcMode: "host", ShmSize: "1gb",
		Volumes: []string{"/dev/shm:/container/shm"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestParseShmSize(t *testing.T) {
	tests := []struct{ input string; want int64 }{
		{"256mb", 256 * 1024 * 1024},
		{"1gb", 1024 * 1024 * 1024},
		{"512kb", 512 * 1024},
		{"1024", 1024},
		{"invalid", 0},
	}
	for _, tt := range tests {
		got := parseShmSize(tt.input)
		if got != tt.want {
			t.Errorf("parseShmSize(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{Name: "svc", IpcMode: "host"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "IPC Namespace") {
		t.Error("missing header")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := mkCollected(compose.Service{Name: "clean"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Total findings:     0") {
		t.Error("expected 0 findings")
	}
}
