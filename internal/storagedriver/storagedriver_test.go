package storagedriver

import (
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

func TestDockerSockMount(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "dind",
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "storagedriver_docker_sock" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected storagedriver_docker_sock finding")
	}
}

func TestSensitiveMountEtcShadow(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "svc",
		Volumes: []string{"/etc/shadow:/app/shadow"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "storagedriver_sensitive_mount" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected storagedriver_sensitive_mount finding for /etc/shadow")
	}
}

func TestSensitiveMountReadOnly(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "svc",
		Volumes: []string{"/etc/shadow:/app/shadow:ro"},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "storagedriver_sensitive_mount" {
				t.Error("should not flag sensitive mount when :ro")
			}
		}
	}
}

func TestHostMountRW(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"/data:/app/data"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "storagedriver_host_mount_rw" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected storagedriver_host_mount_rw finding")
	}
}

func TestHostMountRO(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"/data:/app/data:ro"},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "storagedriver_host_mount_rw" {
				t.Error("should not flag host mount when :ro")
			}
		}
	}
}

func TestNoReadOnlyRoot(t *testing.T) {
	c := makeCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "storagedriver_no_readonly_root" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected storagedriver_no_readonly_root finding")
	}
}

func TestReadOnlyRoot(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:     "web",
		ReadOnly: true,
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "storagedriver_no_readonly_root" {
				t.Error("should not flag when read_only is true")
			}
		}
	}
}

func TestTmpfsNoSizeLimit(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:  "cache",
		Tmpfs: []string{"/tmp"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "storagedriver_tmpfs_no_size" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected storagedriver_tmpfs_no_size finding")
	}
}

func TestTmpfsWithSize(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:  "cache",
		Tmpfs: []string{"/tmp:size=64m"},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "storagedriver_tmpfs_no_size" {
				t.Error("should not flag tmpfs with size limit")
			}
		}
	}
}

func TestPrivilegedStorage(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:       "priv",
		Privileged: true,
		Volumes:    []string{"/data:/mnt/data"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "storagedriver_privileged_storage" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected storagedriver_privileged_storage finding")
	}
}

func TestPrivilegedNoVolumes(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:       "priv-no-vol",
		Privileged: true,
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "storagedriver_privileged_storage" {
				t.Error("should not flag privileged without volume mounts")
			}
		}
	}
}

func TestSummaryCounters(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a"},
		compose.Service{
			Name:    "b",
			Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
		},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.DockerSockMount != 1 {
		t.Errorf("expected 1 docker sock mount, got %d", r.Summary.DockerSockMount)
	}
	if r.Summary.NoReadOnlyRoot != 2 {
		t.Errorf("expected 2 no-readonly-root, got %d", r.Summary.NoReadOnlyRoot)
	}
}

func TestFormatText(t *testing.T) {
	c := makeCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !contains(text, "Storage Driver") {
		t.Error("expected header in text output")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestMultipleVolumeFindings(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "multi",
		Volumes: []string{
			"/var/run/docker.sock:/var/run/docker.sock",
			"/etc/shadow:/shadow",
			"/data:/data",
		},
	})
	r := Analyze(c)
	ruleCount := make(map[string]int)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			ruleCount[f.Rule]++
		}
	}
	if ruleCount["storagedriver_docker_sock"] != 1 {
		t.Errorf("expected 1 docker_sock, got %d", ruleCount["storagedriver_docker_sock"])
	}
	if ruleCount["storagedriver_sensitive_mount"] < 1 {
		t.Error("expected at least 1 sensitive_mount finding")
	}
}

func TestNamedVolume(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "db",
		Volumes: []string{"pgdata:/var/lib/postgresql/data"},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "storagedriver_host_mount_rw" {
				t.Error("should not flag named volumes as host mount RW")
			}
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
