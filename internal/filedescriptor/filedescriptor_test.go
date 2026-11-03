package filedescriptor

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	cf := compose.File{Path: "docker-compose.yml", Services: services}
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{cf}}
}

func findRule(results []ServiceResult, rule string) bool {
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return true
			}
		}
	}
	return false
}

func TestExcessiveNofile(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Ulimits: map[string]compose.UlimitValue{"nofile": {Soft: 65536, Hard: 2000000}},
	})
	r := Analyze(c)
	if !findRule(r.Services, "fd_excessive_nofile") {
		t.Error("expected fd_excessive_nofile for hard limit > 1048576")
	}
}

func TestReasonableNofile(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Ulimits: map[string]compose.UlimitValue{"nofile": {Soft: 65536, Hard: 65536}},
	})
	r := Analyze(c)
	if findRule(r.Services, "fd_excessive_nofile") {
		t.Error("should not flag reasonable nofile limit")
	}
}

func TestUnlimitedNofile(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Ulimits: map[string]compose.UlimitValue{"nofile": {Soft: -1, Hard: -1}},
	})
	r := Analyze(c)
	if !findRule(r.Services, "fd_unlimited_nofile") {
		t.Error("expected fd_unlimited_nofile for -1 limit")
	}
}

func TestUnlimitedSoftOnly(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Ulimits: map[string]compose.UlimitValue{"nofile": {Soft: -1, Hard: 65536}},
	})
	r := Analyze(c)
	if !findRule(r.Services, "fd_unlimited_nofile") {
		t.Error("expected fd_unlimited_nofile for soft=-1")
	}
}

func TestPrivilegedNoNofile(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "web",
		Privileged: true,
	})
	r := Analyze(c)
	if !findRule(r.Services, "fd_no_nofile_limit") {
		t.Error("expected fd_no_nofile_limit for privileged without nofile")
	}
}

func TestPrivilegedWithNofile(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "web",
		Privileged: true,
		Ulimits:    map[string]compose.UlimitValue{"nofile": {Soft: 1024, Hard: 4096}},
	})
	r := Analyze(c)
	if findRule(r.Services, "fd_no_nofile_limit") {
		t.Error("should not flag privileged with explicit nofile limit")
	}
}

func TestDevFdMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Volumes: []string{"/dev/fd:/dev/fd"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "fd_dev_fd_mount") {
		t.Error("expected fd_dev_fd_mount for /dev/fd volume")
	}
}

func TestProcSelfFdMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Volumes: []string{"/proc/self/fd:/proc/fd"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "fd_proc_fd_mount") {
		t.Error("expected fd_proc_fd_mount for /proc/self/fd volume")
	}
}

func TestProc1FdMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Volumes: []string{"/proc/1/fd:/container/fd"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "fd_proc_fd_mount") {
		t.Error("expected fd_proc_fd_mount for /proc/1/fd volume")
	}
}

func TestDockerSocketMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "fd_socket_mount") {
		t.Error("expected fd_socket_mount for docker.sock")
	}
}

func TestSockFileSuffix(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Volumes: []string{"/run/app.sock:/run/app.sock"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "fd_socket_mount") {
		t.Error("expected fd_socket_mount for .sock file")
	}
}

func TestSocketFileSuffix(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Volumes: []string{"/run/app.socket:/run/app.socket"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "fd_socket_mount") {
		t.Error("expected fd_socket_mount for .socket file")
	}
}

func TestNormalVolumeNotFlagged(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Volumes: []string{"./data:/app/data"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestDevFdDevice(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Devices: []string{"/dev/fd0:/dev/fd0"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "fd_dev_fd_mount") {
		t.Error("expected fd_dev_fd_mount for /dev/fd device mapping")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleServices(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "web"},
		compose.Service{Name: "worker"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Ulimits: map[string]compose.UlimitValue{"nofile": {Soft: -1, Hard: -1}},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "File Descriptor") {
		t.Error("expected 'File Descriptor' in output")
	}
	if !strings.Contains(text, "web") {
		t.Error("expected service name in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "no findings") {
		t.Error("expected 'no findings' in output")
	}
}

func TestReportPath(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Path != "/test" {
		t.Errorf("expected path /test, got %s", r.Path)
	}
}

func TestSummaryTotals(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "a", Privileged: true},
		compose.Service{Name: "b", Ulimits: map[string]compose.UlimitValue{"nofile": {Soft: -1, Hard: -1}}},
	)
	r := Analyze(c)
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}
