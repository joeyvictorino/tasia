package cgroupescape

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
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

func findRule(r Report, rule string) *Finding {
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return &f
			}
		}
	}
	return nil
}

func countRule(r Report, rule string) int {
	count := 0
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				count++
			}
		}
	}
	return count
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestCleanService(t *testing.T) {
	s := svc("web")
	s.Volumes = []string{"/data:/app/data"}
	c := mkCollected(s)
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestCgroupFSMount(t *testing.T) {
	s := svc("escape")
	s.Volumes = []string{"/sys/fs/cgroup:/sys/fs/cgroup"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "cgroup_fs_mount") == nil {
		t.Fatal("expected cgroup_fs_mount finding")
	}
}

func TestCgroupFSMountReadOnly(t *testing.T) {
	s := svc("ro-cg")
	s.Volumes = []string{"/sys/fs/cgroup:/sys/fs/cgroup:ro"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "cgroup_fs_mount") == nil {
		t.Fatal("even read-only cgroup mount should trigger cgroup_fs_mount")
	}
	if findRule(r, "writable_cgroup_mount") != nil {
		t.Fatal("read-only cgroup mount should not trigger writable_cgroup_mount from container path check")
	}
}

func TestWritableCgroupMount(t *testing.T) {
	s := svc("rw-cg")
	s.Volumes = []string{"/sys/fs/cgroup:/sys/fs/cgroup"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "writable_cgroup_mount") == nil {
		t.Fatal("expected writable_cgroup_mount finding")
	}
}

func TestWritableCgroupHostPath(t *testing.T) {
	s := svc("host-cg")
	s.Volumes = []string{"/sys/fs/cgroup:/mnt/cgroups"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "writable_cgroup_mount") == nil {
		t.Fatal("expected writable_cgroup_mount for host cgroup path")
	}
}

func TestReleaseAgentVolume(t *testing.T) {
	s := svc("agent")
	s.Volumes = []string{"/tmp/exploit:/sys/fs/cgroup/release_agent"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "release_agent_risk") == nil {
		t.Fatal("expected release_agent_risk finding")
	}
}

func TestReleaseAgentCommand(t *testing.T) {
	s := svc("cmd-agent")
	s.Command = []string{"sh", "-c", "echo 1 > /sys/fs/cgroup/notify_on_release"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "release_agent_risk") == nil {
		t.Fatal("expected release_agent_risk for notify_on_release in command")
	}
}

func TestReleaseAgentEntrypoint(t *testing.T) {
	s := svc("ep-agent")
	s.Entrypoint = []string{"sh", "-c", "cat /sys/fs/cgroup/release_agent"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "release_agent_risk") == nil {
		t.Fatal("expected release_agent_risk for release_agent in entrypoint")
	}
}

func TestPrivilegedCgroupAccess(t *testing.T) {
	s := svc("priv")
	s.Privileged = true
	s.Volumes = []string{"/sys/fs/cgroup:/sys/fs/cgroup"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "privileged_cgroup_access") == nil {
		t.Fatal("expected privileged_cgroup_access for privileged + cgroup mount")
	}
}

func TestSysAdminCapability(t *testing.T) {
	s := svc("admin")
	s.CapAdd = []string{"SYS_ADMIN"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "privileged_cgroup_access") == nil {
		t.Fatal("expected privileged_cgroup_access for SYS_ADMIN capability")
	}
}

func TestAllCapability(t *testing.T) {
	s := svc("all-caps")
	s.CapAdd = []string{"ALL"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "privileged_cgroup_access") == nil {
		t.Fatal("expected privileged_cgroup_access for ALL capability")
	}
}

func TestNoSysAdminCapNoFinding(t *testing.T) {
	s := svc("limited")
	s.CapAdd = []string{"NET_ADMIN"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "privileged_cgroup_access") != nil {
		t.Fatal("NET_ADMIN should not trigger privileged_cgroup_access")
	}
}

func TestCgroupParent(t *testing.T) {
	s := svc("custom-cg")
	s.CgroupParent = "/docker/custom"
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "cgroup_ns_sharing") == nil {
		t.Fatal("expected cgroup_ns_sharing for custom cgroup_parent")
	}
}

func TestHostPidPrivileged(t *testing.T) {
	s := svc("host-pid")
	s.PidMode = "host"
	s.Privileged = true
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "cgroup_ns_sharing") == nil {
		t.Fatal("expected cgroup_ns_sharing for host PID + privileged")
	}
}

func TestHostPidNotPrivilegedNoFinding(t *testing.T) {
	s := svc("host-pid-safe")
	s.PidMode = "host"
	s.Privileged = false
	c := mkCollected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "cgroup_ns_sharing" && strings.Contains(f.Message, "host PID") {
				found = true
			}
		}
	}
	if found {
		t.Fatal("host PID without privileged should not trigger host PID cgroup_ns_sharing")
	}
}

func TestUnsafeCgroupPathEnv(t *testing.T) {
	s := svc("env-cg")
	s.Environment = []string{"CGROUP_DIR=/sys/fs/cgroup/memory"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "unsafe_cgroup_path") == nil {
		t.Fatal("expected unsafe_cgroup_path for env referencing cgroup path")
	}
}

func TestSafeEnvNoFinding(t *testing.T) {
	s := svc("safe")
	s.Environment = []string{"APP_PORT=8080"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "unsafe_cgroup_path") != nil {
		t.Fatal("normal env should not trigger unsafe_cgroup_path")
	}
}

func TestSummaryCounts(t *testing.T) {
	s := svc("complex")
	s.Volumes = []string{"/sys/fs/cgroup:/sys/fs/cgroup"}
	s.Privileged = true
	s.CgroupParent = "/custom"
	c := mkCollected(s)
	r := Analyze(c)
	if r.Summary.CgroupFSMounts < 1 {
		t.Fatal("expected CgroupFSMounts > 0")
	}
	if r.Summary.PrivilegedCgroupAccess < 1 {
		t.Fatal("expected PrivilegedCgroupAccess > 0")
	}
	if r.Summary.CgroupNSSharing < 1 {
		t.Fatal("expected CgroupNSSharing > 0")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text")
	}
	if !strings.Contains(text, "0 findings") {
		t.Fatal("expected 0 findings in output")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	s := svc("escape-svc")
	s.Volumes = []string{"/sys/fs/cgroup:/sys/fs/cgroup"}
	c := mkCollected(s)
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "escape-svc") {
		t.Fatal("expected service name in text output")
	}
	if !strings.Contains(text, "Cgroup Escape") {
		t.Fatal("expected header in text output")
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/project"}
	r := Analyze(c)
	if r.Path != "/project" {
		t.Fatalf("expected /project, got %s", r.Path)
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("a")
	s2 := svc("b")
	c := mkCollected(s1, s2)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestProcCgroupsMount(t *testing.T) {
	s := svc("proc")
	s.Volumes = []string{"/proc/cgroups:/host/cgroups"}
	c := mkCollected(s)
	r := Analyze(c)
	if findRule(r, "writable_cgroup_mount") == nil {
		t.Fatal("expected writable_cgroup_mount for /proc/cgroups host path")
	}
}
