package ipcaudit

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

func TestHostIPC(t *testing.T) {
	c := collected(compose.Service{Name: "app", IpcMode: "host"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "ipc_host_namespace") {
		t.Error("expected ipc_host_namespace for ipc: host")
	}
	if r.Summary.HostIPC != 1 {
		t.Errorf("expected 1 host_ipc, got %d", r.Summary.HostIPC)
	}
}

func TestPrivateIPC(t *testing.T) {
	c := collected(compose.Service{Name: "app", IpcMode: "private"})
	r := Analyze(c)
	if hasRule(r.Services[0], "ipc_host_namespace") {
		t.Error("should not flag private ipc mode")
	}
}

func TestSharedIPCWithService(t *testing.T) {
	c := collected(compose.Service{Name: "sidecar", IpcMode: "service:app"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "ipc_shared_namespace") {
		t.Error("expected ipc_shared_namespace for ipc: service:app")
	}
	if r.Summary.ShareableIPC != 1 {
		t.Errorf("expected 1 shareable_ipc, got %d", r.Summary.ShareableIPC)
	}
}

func TestSharedIPCWithContainer(t *testing.T) {
	c := collected(compose.Service{Name: "sidecar", IpcMode: "container:mycontainer"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "ipc_shared_namespace") {
		t.Error("expected ipc_shared_namespace for ipc: container:mycontainer")
	}
}

func TestLargeShmSize(t *testing.T) {
	c := collected(compose.Service{Name: "ml", ShmSize: "4g"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "ipc_large_shm") {
		t.Error("expected ipc_large_shm for shm_size: 4g")
	}
	if r.Summary.LargeShmSize != 1 {
		t.Errorf("expected 1 large_shm, got %d", r.Summary.LargeShmSize)
	}
}

func TestReasonableShmSize(t *testing.T) {
	c := collected(compose.Service{Name: "app", ShmSize: "256m"})
	r := Analyze(c)
	if hasRule(r.Services[0], "ipc_large_shm") {
		t.Error("should not flag reasonable shm_size 256m")
	}
}

func TestBoundaryShmSize(t *testing.T) {
	c := collected(compose.Service{Name: "app", ShmSize: "2g"})
	r := Analyze(c)
	if hasRule(r.Services[0], "ipc_large_shm") {
		t.Error("shm_size equal to 2g threshold should not be flagged")
	}
}

func TestNoShmLimit(t *testing.T) {
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "ipc_no_shm_limit") {
		t.Error("expected ipc_no_shm_limit when no shm_size or ipc mode set")
	}
	if r.Summary.NoShmLimit != 1 {
		t.Errorf("expected 1 no_shm_limit, got %d", r.Summary.NoShmLimit)
	}
}

func TestNoShmLimitNotFlaggedWithIPC(t *testing.T) {
	c := collected(compose.Service{Name: "web", IpcMode: "host"})
	r := Analyze(c)
	if hasRule(r.Services[0], "ipc_no_shm_limit") {
		t.Error("should not flag no_shm_limit when ipc mode is set")
	}
}

func TestPrivilegedHostIPC(t *testing.T) {
	c := collected(compose.Service{Name: "agent", Privileged: true, IpcMode: "host"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "ipc_privileged_host") {
		t.Error("expected ipc_privileged_host for privileged + host ipc")
	}
	if r.Summary.PrivilegedHostIPC != 1 {
		t.Errorf("expected 1 privileged_host_ipc, got %d", r.Summary.PrivilegedHostIPC)
	}
}

func TestPrivilegedPrivateIPC(t *testing.T) {
	c := collected(compose.Service{Name: "agent", Privileged: true, IpcMode: "private"})
	r := Analyze(c)
	if hasRule(r.Services[0], "ipc_privileged_host") {
		t.Error("should not flag privileged_host when ipc is private")
	}
}

func TestDevShmMount(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/dev/shm:/dev/shm"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "ipc_devshm_mount") {
		t.Error("expected ipc_devshm_mount for /dev/shm volume mount")
	}
}

func TestNoDevShmMount(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/data:/app/data"}})
	r := Analyze(c)
	if hasRule(r.Services[0], "ipc_devshm_mount") {
		t.Error("should not flag devshm_mount for regular volumes")
	}
}

func TestMultipleServices(t *testing.T) {
	c := collected(
		compose.Service{Name: "web"},
		compose.Service{Name: "app", IpcMode: "host"},
		compose.Service{Name: "worker", ShmSize: "4g"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.HostIPC != 1 {
		t.Errorf("expected 1 host_ipc, got %d", r.Summary.HostIPC)
	}
	if r.Summary.LargeShmSize != 1 {
		t.Errorf("expected 1 large_shm, got %d", r.Summary.LargeShmSize)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{Name: "web", IpcMode: "host"})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{Name: "app", IpcMode: "host"})
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
