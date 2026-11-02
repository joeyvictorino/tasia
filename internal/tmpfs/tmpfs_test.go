package tmpfs

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeNoTmpfs(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name: "web",
			}},
		}},
	}
	r := Analyze(c)
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	if r.Summary.ServicesWithTmpfs != 0 {
		t.Errorf("expected 0 services with tmpfs, got %d", r.Summary.ServicesWithTmpfs)
	}
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyzeTmpfsNoSizeLimit(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:  "cache",
				Tmpfs: []string{"/tmp"},
			}},
		}},
	}
	r := Analyze(c)
	svc := r.Services[0]
	if len(svc.TmpfsMounts) != 1 {
		t.Fatalf("expected 1 tmpfs mount, got %d", len(svc.TmpfsMounts))
	}
	found := false
	for _, f := range svc.Findings {
		if f.Category == "size" {
			found = true
		}
	}
	if !found {
		t.Error("expected size finding for tmpfs without size limit")
	}
}

func TestAnalyzeTmpfsWithSizeLimit(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:  "cache",
				Tmpfs: []string{"/tmp:size=64m"},
			}},
		}},
	}
	r := Analyze(c)
	svc := r.Services[0]
	for _, f := range svc.Findings {
		if f.Category == "size" {
			t.Error("should not report size finding when size= is set")
		}
	}
}

func TestAnalyzeSensitivePath(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:  "risky",
				Tmpfs: []string{"/etc:size=10m"},
			}},
		}},
	}
	r := Analyze(c)
	svc := r.Services[0]
	found := false
	for _, f := range svc.Findings {
		if f.Category == "sensitive_path" && f.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Error("expected sensitive_path finding for /etc")
	}
}

func TestAnalyzeNoexecNosuid(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:  "app",
				Tmpfs: []string{"/tmp:size=64m,noexec,nosuid"},
			}},
		}},
	}
	r := Analyze(c)
	svc := r.Services[0]
	for _, f := range svc.Findings {
		if f.Category == "exec" || f.Category == "suid" {
			t.Errorf("unexpected finding %s when noexec,nosuid are set", f.Category)
		}
	}
}

func TestAnalyzeMissingNoexec(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:  "app",
				Tmpfs: []string{"/tmp:size=64m,nosuid"},
			}},
		}},
	}
	r := Analyze(c)
	svc := r.Services[0]
	found := false
	for _, f := range svc.Findings {
		if f.Category == "exec" {
			found = true
		}
	}
	if !found {
		t.Error("expected exec finding when noexec is missing")
	}
}

func TestAnalyzeVolumeTmpfs(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:    "svc",
				Volumes: []string{"tmpfs:/data"},
			}},
		}},
	}
	r := Analyze(c)
	svc := r.Services[0]
	found := false
	for _, f := range svc.Findings {
		if f.Category == "volume_tmpfs" {
			found = true
		}
	}
	if !found {
		t.Error("expected volume_tmpfs finding")
	}
}

func TestSummary(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "a", Tmpfs: []string{"/tmp", "/run"}},
				{Name: "b"},
			},
		}},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.ServicesWithTmpfs != 1 {
		t.Errorf("expected 1 with tmpfs, got %d", r.Summary.ServicesWithTmpfs)
	}
	if r.Summary.TotalMounts != 2 {
		t.Errorf("expected 2 mounts, got %d", r.Summary.TotalMounts)
	}
}

func TestFormatText(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{Name: "svc", Tmpfs: []string{"/tmp"}}},
		}},
	}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output even for empty scan")
	}
}

func TestParseTmpfsMount(t *testing.T) {
	tests := []struct {
		mount    string
		wantPath string
		wantOpts string
	}{
		{"/tmp", "/tmp", ""},
		{"/tmp:size=64m", "/tmp", "size=64m"},
		{"/run:size=128m,noexec,nosuid", "/run", "size=128m,noexec,nosuid"},
	}
	for _, tt := range tests {
		path, opts := parseTmpfsMount(tt.mount)
		if path != tt.wantPath {
			t.Errorf("parseTmpfsMount(%q) path = %q, want %q", tt.mount, path, tt.wantPath)
		}
		if opts != tt.wantOpts {
			t.Errorf("parseTmpfsMount(%q) opts = %q, want %q", tt.mount, opts, tt.wantOpts)
		}
	}
}

func TestIsSensitivePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/etc", true},
		{"/etc/", true},
		{"/etc/ssl", true},
		{"/var/run", true},
		{"/home", true},
		{"/tmp", false},
		{"/data", false},
		{"/opt", false},
	}
	for _, tt := range tests {
		got := isSensitivePath(tt.path)
		if got != tt.want {
			t.Errorf("isSensitivePath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
