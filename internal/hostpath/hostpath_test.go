package hostpath

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

func hasRule(sr ServiceResult, rule string) bool {
	for _, f := range sr.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestRootMount(t *testing.T) {
	c := collected(compose.Service{
		Name:    "agent",
		Volumes: []string{"/:/host"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "hostpath_root_mount") {
		t.Error("expected hostpath_root_mount for /:/host")
	}
	if r.Summary.RootMounts != 1 {
		t.Errorf("expected 1 root mount, got %d", r.Summary.RootMounts)
	}
}

func TestDockerSocketMount(t *testing.T) {
	c := collected(compose.Service{
		Name:    "deployer",
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "hostpath_docker_socket") {
		t.Error("expected hostpath_docker_socket")
	}
	if r.Summary.DockerSockets != 1 {
		t.Errorf("expected 1 docker socket, got %d", r.Summary.DockerSockets)
	}
}

func TestRunDockerSocketMount(t *testing.T) {
	c := collected(compose.Service{
		Name:    "deployer",
		Volumes: []string{"/run/docker.sock:/var/run/docker.sock"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "hostpath_docker_socket") {
		t.Error("expected hostpath_docker_socket for /run/docker.sock")
	}
}

func TestProcMount(t *testing.T) {
	c := collected(compose.Service{
		Name:    "monitor",
		Volumes: []string{"/proc:/host/proc"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "hostpath_proc_sys") {
		t.Error("expected hostpath_proc_sys for /proc mount")
	}
}

func TestSysMountReadOnly(t *testing.T) {
	c := collected(compose.Service{
		Name:    "metrics",
		Volumes: []string{"/sys:/host/sys:ro"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "hostpath_proc_sys") {
		t.Error("expected hostpath_proc_sys for /sys mount even if ro")
	}
	for _, f := range r.Services[0].Findings {
		if f.Rule == "hostpath_proc_sys" && f.Level != "medium" {
			t.Errorf("expected medium severity for ro /sys mount, got %s", f.Level)
		}
	}
}

func TestSensitiveRWMount(t *testing.T) {
	c := collected(compose.Service{
		Name:    "backup",
		Volumes: []string{"/etc:/host-etc"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "hostpath_sensitive_rw") {
		t.Error("expected hostpath_sensitive_rw for /etc mount without ro")
	}
}

func TestSensitiveROSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:    "reader",
		Volumes: []string{"/etc:/host-etc:ro"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "hostpath_sensitive_rw") {
		t.Error("should not flag hostpath_sensitive_rw for read-only mount")
	}
}

func TestNonSensitivePath(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"/data/myapp:/app/data"},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings for /data/myapp, got %d", len(r.Services[0].Findings))
	}
}

func TestNamedVolumeIgnored(t *testing.T) {
	c := collected(compose.Service{
		Name:    "db",
		Volumes: []string{"pgdata:/var/lib/postgresql"},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings for named volume, got %d", len(r.Services[0].Findings))
	}
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{Name: "clean"})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for clean service, got %d", len(r.Services[0].Findings))
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleViolations(t *testing.T) {
	c := collected(compose.Service{
		Name:    "allbad",
		Volumes: []string{"/:/host", "/var/run/docker.sock:/var/run/docker.sock", "/proc:/proc", "/etc:/etc"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings < 4 {
		t.Errorf("expected at least 4 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{
		Name:    "agent",
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{
		Name:    "web",
		Volumes: []string{"/etc:/etc"},
	})
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var r2 Report
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if r2.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service after round-trip, got %d", r2.Summary.TotalServices)
	}
}
