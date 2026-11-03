package volperm

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: svcs},
		},
	}
}

func TestNoVolumes(t *testing.T) {
	c := makeCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestDockerSocket(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "volperm_docker_socket" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected volperm_docker_socket finding")
	}
}

func TestRootMountRW(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "debug",
		Volumes: []string{"/:/host"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "volperm_root_rw" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected volperm_root_rw finding")
	}
}

func TestRootMountRO(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "readonly",
		Volumes: []string{"/:/host:ro"},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "volperm_root_rw" {
				t.Error("should not flag root mount with :ro")
			}
		}
	}
}

func TestSensitivePath(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"/etc:/config"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "volperm_sensitive_path" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected volperm_sensitive_path finding for /etc")
	}
}

func TestSensitivePathRO(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"/etc:/config:ro"},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "volperm_sensitive_path" {
				t.Error("should not flag sensitive path with :ro")
			}
		}
	}
}

func TestWritableHostMount(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"/data/app:/app"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "volperm_writable_host" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected volperm_writable_host finding")
	}
}

func TestWritableHostMountRO(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"/data/app:/app:ro"},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "volperm_writable_host" {
				t.Error("should not flag host mount with :ro")
			}
		}
	}
}

func TestSharedPropagation(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "builder",
		Volumes: []string{"/mnt/data:/data:rw,rshared"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "volperm_recursive_bind" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected volperm_recursive_bind finding for rshared")
	}
}

func TestWorldWritableTmp(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"/tmp/shared:/shared"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "volperm_world_writable" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected volperm_world_writable finding for /tmp mount")
	}
}

func TestNamedVolume(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "db",
		Volumes: []string{"pgdata:/var/lib/postgresql/data"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for named volume, got %d", r.Summary.TotalFindings)
	}
}

func TestShadowFile(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "admin",
		Volumes: []string{"/etc/shadow:/etc/shadow"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "volperm_sensitive_path" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected volperm_sensitive_path finding for /etc/shadow")
	}
}

func TestProcMount(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "monitor",
		Volumes: []string{"/proc:/host/proc"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "volperm_sensitive_path" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected volperm_sensitive_path finding for /proc")
	}
}

func TestMultipleServices(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"}},
		compose.Service{Name: "b", Volumes: []string{"/data:/data"}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestSummary(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"}},
		compose.Service{Name: "b", Volumes: []string{"/:/host"}},
	)
	r := Analyze(c)
	if r.Summary.DockerSocketMount != 1 {
		t.Errorf("expected 1 docker socket mount, got %d", r.Summary.DockerSocketMount)
	}
	if r.Summary.RootMountRW != 1 {
		t.Errorf("expected 1 root mount, got %d", r.Summary.RootMountRW)
	}
}

func TestFormatText(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !strings.Contains(text, "Volume Permission") {
		t.Error("expected header in text output")
	}
}

func TestEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestRunDockerSocket(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Volumes: []string{"/run/docker.sock:/var/run/docker.sock"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "volperm_docker_socket" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected volperm_docker_socket for /run/docker.sock")
	}
}
