package mntns

import (
	"encoding/json"
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

func TestEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestNoVolumes(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "web", ReadOnly: true}))
	if r.Summary.TotalServices != 1 {
		t.Fatalf("expected 1 service")
	}
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID != "mntns_no_readonly_root" {
				t.Fatalf("unexpected finding: %s", f.RuleID)
			}
		}
	}
}

func TestRootFSMount(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "evil", Volumes: []string{"/:/host"}, ReadOnly: true,
	}))
	if r.Summary.RootFSMount != 1 {
		t.Fatalf("expected 1 root FS mount, got %d", r.Summary.RootFSMount)
	}
}

func TestDockerSocketMount(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "dind", Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"}, ReadOnly: true,
	}))
	if r.Summary.DockerSockMount != 1 {
		t.Fatalf("expected 1 docker socket mount")
	}
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "mntns_docker_sock" && f.Severity != "critical" {
				t.Fatalf("writable docker socket should be critical, got %s", f.Severity)
			}
		}
	}
}

func TestDockerSocketReadOnly(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "monitor", Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock:ro"}, ReadOnly: true,
	}))
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "mntns_docker_sock" && f.Severity != "high" {
				t.Fatalf("read-only docker socket should be high, got %s", f.Severity)
			}
		}
	}
}

func TestSensitiveMount(t *testing.T) {
	for _, path := range []string{"/etc", "/proc", "/sys", "/root", "/home", "/boot", "/dev"} {
		r := Analyze(collected(compose.Service{
			Name: "svc", Volumes: []string{path + ":/mnt:ro"}, ReadOnly: true,
		}))
		if r.Summary.SensitiveMount != 1 {
			t.Fatalf("expected sensitive mount for %s, got %d", path, r.Summary.SensitiveMount)
		}
	}
}

func TestWritableHostMount(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "app", Volumes: []string{"/data:/app/data"}, ReadOnly: true,
	}))
	if r.Summary.WritableHostMount != 1 {
		t.Fatalf("expected 1 writable host mount, got %d", r.Summary.WritableHostMount)
	}
}

func TestReadOnlyHostMount(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "app", Volumes: []string{"/data:/app/data:ro"}, ReadOnly: true,
	}))
	if r.Summary.WritableHostMount != 0 {
		t.Fatalf("read-only mount should not be flagged as writable")
	}
}

func TestNoReadOnlyRoot(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc"}))
	if r.Summary.NoReadOnlyRoot != 1 {
		t.Fatalf("expected no-readonly-root finding, got %d", r.Summary.NoReadOnlyRoot)
	}
}

func TestReadOnlyRootSkips(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", ReadOnly: true}))
	if r.Summary.NoReadOnlyRoot != 0 {
		t.Fatal("read_only: true should skip no-readonly-root")
	}
}

func TestPrivilegedSkipsReadOnlyRoot(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "priv", Privileged: true}))
	if r.Summary.NoReadOnlyRoot != 0 {
		t.Fatal("privileged services should skip no-readonly-root")
	}
}

func TestNamedVolume(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "db", Volumes: []string{"pgdata:/var/lib/postgres"}, ReadOnly: true,
	}))
	if r.Summary.WritableHostMount != 0 && r.Summary.SensitiveMount != 0 {
		t.Fatal("named volumes should not trigger host mount findings")
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "svc", Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	}))
	text := FormatText(r)
	if !strings.Contains(text, "Mount Namespace Security Audit") {
		t.Fatal("expected header in text")
	}
	if !strings.Contains(text, "mntns_docker_sock") {
		t.Fatal("expected docker socket rule in text")
	}
}

func TestFormatJSON(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "x", ReadOnly: true}))
	var out Report
	if err := json.Unmarshal([]byte(FormatJSON(r)), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if out.Summary.TotalServices != 1 {
		t.Fatal("JSON round-trip failed")
	}
}

func TestParseVolume(t *testing.T) {
	tests := []struct {
		vol  string
		host string
		ro   bool
	}{
		{"data", "", false},
		{"/host:/cont", "/host", false},
		{"/host:/cont:ro", "/host", true},
		{"/host:/cont:rw", "/host", false},
	}
	for _, tt := range tests {
		h, _, ro := parseVolume(tt.vol)
		if h != tt.host || ro != tt.ro {
			t.Errorf("parseVolume(%q) = (%q, _, %v), want (%q, _, %v)", tt.vol, h, ro, tt.host, tt.ro)
		}
	}
}
