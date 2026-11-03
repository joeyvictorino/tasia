package shmsize

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}},
	}
}

func TestNoServices(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("want 0, got %d", r.Summary.TotalServices)
	}
}

func TestLargeShm(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "ml", ShmSize: "2g"}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "shm_large" {
			found = true
			if f.Severity != "medium" {
				t.Fatalf("want medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected shm_large finding for 2g")
	}
}

func TestLargeShmMB(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "ml", ShmSize: "2048m"}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "shm_large" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected shm_large finding for 2048m")
	}
}

func TestSmallShmNoFinding(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", ShmSize: "64m"}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "shm_large" {
			t.Fatal("should not flag 64m")
		}
	}
}

func TestNoShmNoFinding(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc"}))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("want 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestDevShmMount(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:    "svc",
		Volumes: []string{"/dev/shm:/dev/shm"},
	}))
	var found bool
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "shm_devshm_mount" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected shm_devshm_mount finding")
	}
}

func TestNormalVolumeNoFinding(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name:    "svc",
		Volumes: []string{"./data:/data"},
	}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "shm_devshm_mount" {
			t.Fatal("should not flag normal volume")
		}
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(collected(
		compose.Service{Name: "a", ShmSize: "4g"},
		compose.Service{Name: "b", Volumes: []string{"/dev/shm:/dev/shm"}},
	))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("want 2, got %d", r.Summary.TotalServices)
	}
	if r.Summary.LargeShm != 1 {
		t.Fatalf("want 1 large shm, got %d", r.Summary.LargeShm)
	}
	if r.Summary.DevShmMount != 1 {
		t.Fatalf("want 1 dev shm mount, got %d", r.Summary.DevShmMount)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", ShmSize: "2g"}))
	text := FormatText(r)
	if text == "" {
		t.Fatal("format text should not be empty")
	}
	if !strings.Contains(text, "Shared Memory") {
		t.Fatal("should contain header")
	}
}

func TestIsLargeShm(t *testing.T) {
	tests := []struct {
		size string
		want bool
	}{
		{"64m", false},
		{"512m", false},
		{"1024m", true},
		{"2048m", true},
		{"1g", true},
		{"2g", true},
		{"256mb", false},
		{"2gb", true},
	}
	for _, tt := range tests {
		got := isLargeShm(tt.size)
		if got != tt.want {
			t.Errorf("isLargeShm(%q) = %v, want %v", tt.size, got, tt.want)
		}
	}
}

func TestHasDevShmMount(t *testing.T) {
	tests := []struct {
		vol  string
		want bool
	}{
		{"/dev/shm:/dev/shm", true},
		{"/dev/shm:/tmp/shm", true},
		{"./data:/data", false},
		{"/tmp:/tmp", false},
		{"myvolume", false},
	}
	for _, tt := range tests {
		got := hasDevShmMount(tt.vol)
		if got != tt.want {
			t.Errorf("hasDevShmMount(%q) = %v, want %v", tt.vol, got, tt.want)
		}
	}
}
