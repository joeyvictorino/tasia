package procmount

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

func TestProcMount(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/proc:/host/proc"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "procmount_proc") {
		t.Error("expected procmount_proc for /proc mount")
	}
	if r.Summary.ProcMounts != 1 {
		t.Errorf("expected 1 proc_mount, got %d", r.Summary.ProcMounts)
	}
}

func TestSysMount(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/sys:/host/sys"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "procmount_sys") {
		t.Error("expected procmount_sys for /sys mount")
	}
	if r.Summary.SysMounts != 1 {
		t.Errorf("expected 1 sys_mount, got %d", r.Summary.SysMounts)
	}
}

func TestCgroupMount(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/sys/fs/cgroup:/sys/fs/cgroup"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "procmount_cgroup") {
		t.Error("expected procmount_cgroup for cgroup mount")
	}
	if r.Summary.CgroupMounts != 1 {
		t.Errorf("expected 1 cgroup_mount, got %d", r.Summary.CgroupMounts)
	}
}

func TestDebugfsMount(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/sys/kernel/debug:/debug"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "procmount_debugfs") {
		t.Error("expected procmount_debugfs for debugfs mount")
	}
	if r.Summary.DebugfsMounts != 1 {
		t.Errorf("expected 1 debugfs_mount, got %d", r.Summary.DebugfsMounts)
	}
}

func TestWritableProcMount(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/proc:/host/proc"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "procmount_writable") {
		t.Error("expected procmount_writable for writable /proc mount")
	}
	if r.Summary.WritableProcSys != 1 {
		t.Errorf("expected 1 writable_proc_sys, got %d", r.Summary.WritableProcSys)
	}
}

func TestReadOnlyProcMount(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/proc:/host/proc:ro"}})
	r := Analyze(c)
	if hasRule(r.Services[0], "procmount_writable") {
		t.Error("should not flag writable for ro mount")
	}
	if !hasRule(r.Services[0], "procmount_proc") {
		t.Error("should still flag procmount_proc even for ro mount")
	}
}

func TestNoDangerousMounts(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/data:/app/data", "/logs:/var/log"}})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings for safe volumes, got %d", len(r.Services[0].Findings))
	}
}

func TestNoVolumes(t *testing.T) {
	c := collected(compose.Service{Name: "app"})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings with no volumes, got %d", len(r.Services[0].Findings))
	}
}

func TestPrivilegedWithProcMount(t *testing.T) {
	c := collected(compose.Service{Name: "agent", Privileged: true, Volumes: []string{"/proc:/host/proc"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "procmount_privileged_mount") {
		t.Error("expected procmount_privileged_mount for privileged + proc mount")
	}
}

func TestPrivilegedWithoutDangerousMount(t *testing.T) {
	c := collected(compose.Service{Name: "agent", Privileged: true, Volumes: []string{"/data:/data"}})
	r := Analyze(c)
	if hasRule(r.Services[0], "procmount_privileged_mount") {
		t.Error("should not flag privileged_mount without dangerous volumes")
	}
}

func TestMultipleServices(t *testing.T) {
	c := collected(
		compose.Service{Name: "web"},
		compose.Service{Name: "monitor", Volumes: []string{"/proc:/host/proc:ro"}},
		compose.Service{Name: "debug", Volumes: []string{"/sys/kernel/debug:/debug"}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.ProcMounts != 1 {
		t.Errorf("expected 1 proc_mount, got %d", r.Summary.ProcMounts)
	}
	if r.Summary.DebugfsMounts != 1 {
		t.Errorf("expected 1 debugfs_mount, got %d", r.Summary.DebugfsMounts)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleDangerousVolumes(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/proc:/proc", "/sys:/sys"}})
	r := Analyze(c)
	if r.Summary.ProcMounts != 1 {
		t.Errorf("expected 1 proc_mount, got %d", r.Summary.ProcMounts)
	}
	if r.Summary.SysMounts != 1 {
		t.Errorf("expected 1 sys_mount, got %d", r.Summary.SysMounts)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/proc:/host/proc"}})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/proc:/host/proc"}})
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

func TestProcSubpath(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/proc/1/ns:/host/ns"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "procmount_proc") {
		t.Error("expected procmount_proc for /proc subpath mount")
	}
}
