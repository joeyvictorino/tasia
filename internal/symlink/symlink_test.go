package symlink

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

func TestIsSensitivePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/etc/passwd", true},
		{"/etc/shadow", true},
		{"/proc", true},
		{"/proc/1/status", true},
		{"/sys", true},
		{"/var/run/docker.sock", true},
		{"/root", true},
		{"/home", true},
		{"/data", false},
		{"/app", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isSensitivePath(tt.path)
		if got != tt.want {
			t.Errorf("isSensitivePath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsSymlinkVulnerablePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/tmp", true},
		{"/tmp/subdir", true},
		{"/var/tmp", true},
		{"/dev/shm", true},
		{"/var/log", true},
		{"/run", true},
		{"/var/run", true},
		{"/app", false},
		{"/data", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isSymlinkVulnerablePath(tt.path)
		if got != tt.want {
			t.Errorf("isSymlinkVulnerablePath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsWritableMount(t *testing.T) {
	tests := []struct {
		spec string
		want bool
	}{
		{"/host:/container", true},
		{"/host:/container:rw", true},
		{"/host:/container:ro", false},
		{"/host:/container:ro,nosuid", false},
		{"volume_name", true},
	}
	for _, tt := range tests {
		got := isWritableMount(tt.spec)
		if got != tt.want {
			t.Errorf("isWritableMount(%q) = %v, want %v", tt.spec, got, tt.want)
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

func TestAnalyzeNoVolumes(t *testing.T) {
	s := svc("web")
	c := collected(s)
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyzeSafeVolumes(t *testing.T) {
	s := svc("web")
	s.Volumes = []string{"/data:/app/data:ro"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for safe volume, got %d", r.Summary.TotalFindings)
	}
}

func TestSymlinkTraversalRisk(t *testing.T) {
	s := svc("agent")
	s.Volumes = []string{"/host/tmp:/tmp"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "symlink_traversal_risk" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected symlink_traversal_risk finding for writable /tmp mount")
	}
}

func TestWritableSensitiveTarget(t *testing.T) {
	s := svc("agent")
	s.Volumes = []string{"/host/etc:/etc/passwd"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "writable_sensitive_target" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected writable_sensitive_target finding")
	}
}

func TestRootFSSymlinkRisk(t *testing.T) {
	s := svc("agent")
	s.Volumes = []string{"/host/root:/"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "rootfs_symlink_risk" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected rootfs_symlink_risk finding for root mount")
	}
}

func TestHostSymlinkSource(t *testing.T) {
	s := svc("agent")
	s.Volumes = []string{"/tmp:/app/data"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "host_symlink_source" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected host_symlink_source finding for /tmp host mount")
	}
}

func TestMissingReadOnlyRoot(t *testing.T) {
	s := svc("agent")
	s.Volumes = []string{"/data:/app/data"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_read_only_root" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected missing_read_only_root finding")
	}
}

func TestReadOnlyRootSuppressesFinding(t *testing.T) {
	s := svc("agent")
	s.Volumes = []string{"/data:/app/data"}
	s.ReadOnly = true
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_read_only_root" {
				t.Fatal("should not flag missing_read_only_root when ReadOnly is true")
			}
		}
	}
}

func TestReadOnlyMountSafe(t *testing.T) {
	s := svc("agent")
	s.Volumes = []string{"/host/tmp:/tmp:ro"}
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "symlink_traversal_risk" {
				t.Fatal("read-only mount should not trigger symlink_traversal_risk")
			}
		}
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("agent1")
	s1.Volumes = []string{"/host/tmp:/tmp"}
	s2 := svc("agent2")
	s2.Volumes = []string{"/data:/app:ro"}
	c := collected(s1, s2)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected at least one finding from agent1")
	}
}

func TestSummaryCountsCorrect(t *testing.T) {
	s := svc("risky")
	s.Volumes = []string{"/host/root:/", "/host/tmp:/tmp"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.RootFSSymlinkRisks < 1 {
		t.Fatal("expected at least 1 rootfs risk")
	}
	if r.Summary.SymlinkTraversalRisks < 1 {
		t.Fatal("expected at least 1 traversal risk")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/test"})
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text output")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	s := svc("agent")
	s.Volumes = []string{"/host/tmp:/tmp"}
	c := collected(s)
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text output")
	}
	if len(text) < 50 {
		t.Fatal("expected substantial text output")
	}
}

func TestContainerPath(t *testing.T) {
	tests := []struct {
		spec string
		want string
	}{
		{"/host:/container", "/container"},
		{"/host:/container:ro", "/container"},
		{"volume_name", "volume_name"},
	}
	for _, tt := range tests {
		got := containerPath(tt.spec)
		if got != tt.want {
			t.Errorf("containerPath(%q) = %q, want %q", tt.spec, got, tt.want)
		}
	}
}

func TestHostPath(t *testing.T) {
	tests := []struct {
		spec string
		want string
	}{
		{"/host:/container", "/host"},
		{"/host:/container:ro", "/host"},
		{"volume_name", "volume_name"},
	}
	for _, tt := range tests {
		got := hostPath(tt.spec)
		if got != tt.want {
			t.Errorf("hostPath(%q) = %q, want %q", tt.spec, got, tt.want)
		}
	}
}
