package cgroupns

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

func TestNoCgroupParent(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "web", MemLimit: "512m"}))
	if r.Summary.TotalServices != 1 {
		t.Fatalf("expected 1 service")
	}
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for service with limits and no cgroup_parent, got %d", r.Summary.TotalFindings)
	}
}

func TestCustomCgroupParent(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "worker", CgroupParent: "mygroup", MemLimit: "256m",
	}))
	if r.Summary.CustomCgroupParent != 1 {
		t.Fatalf("expected 1 custom cgroup parent, got %d", r.Summary.CustomCgroupParent)
	}
	found := false
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "cgroupns_custom_parent" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected cgroupns_custom_parent finding")
	}
}

func TestHostCgroup(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "agent", CgroupParent: "/", MemLimit: "1g",
	}))
	if r.Summary.HostCgroup != 1 {
		t.Fatalf("expected 1 host cgroup, got %d", r.Summary.HostCgroup)
	}
}

func TestHostCgroupAbsolutePath(t *testing.T) {
	r := Analyze(collected(compose.Service{
		Name: "svc", CgroupParent: "/system.slice", MemLimit: "512m",
	}))
	if r.Summary.HostCgroup != 1 {
		t.Fatalf("expected host cgroup finding for absolute path")
	}
}

func TestSharedCgroup(t *testing.T) {
	r := Analyze(collected(
		compose.Service{Name: "a", CgroupParent: "shared", MemLimit: "256m"},
		compose.Service{Name: "b", CgroupParent: "shared", MemLimit: "256m"},
	))
	if r.Summary.SharedCgroup != 2 {
		t.Fatalf("expected 2 shared cgroup findings, got %d", r.Summary.SharedCgroup)
	}
}

func TestNoLimits(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "bare"}))
	if r.Summary.NoCgroupLimits != 1 {
		t.Fatalf("expected 1 no-limits finding, got %d", r.Summary.NoCgroupLimits)
	}
}

func TestLimitsMemOnly(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "mem", MemLimit: "128m"}))
	if r.Summary.NoCgroupLimits != 0 {
		t.Fatalf("mem_limit should count as having limits")
	}
}

func TestLimitsCPUOnly(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "cpu", CPUs: "0.5"}))
	if r.Summary.NoCgroupLimits != 0 {
		t.Fatalf("cpus should count as having limits")
	}
}

func TestLimitsPidsOnly(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "pid", PidsLimit: 100}))
	if r.Summary.NoCgroupLimits != 0 {
		t.Fatalf("pids_limit should count as having limits")
	}
}

func TestPrivilegedSkipsNoLimits(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "priv", Privileged: true}))
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "cgroupns_no_limits" {
				t.Fatal("privileged services should not flag no-limits")
			}
		}
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "svc", CgroupParent: "/root"}))
	text := FormatText(r)
	if !strings.Contains(text, "Cgroup Namespace Isolation Audit") {
		t.Fatal("expected header in text output")
	}
	if !strings.Contains(text, "cgroupns_host_cgroup") {
		t.Fatal("expected host cgroup rule in text")
	}
}

func TestFormatJSON(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "x", CgroupParent: "grp", MemLimit: "1g"}))
	var out Report
	if err := json.Unmarshal([]byte(FormatJSON(r)), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if out.Summary.TotalServices != 1 {
		t.Fatal("JSON round-trip failed")
	}
}

func TestMultipleFiles(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "a.yml", Services: []compose.Service{{Name: "svc1", CgroupParent: "shared"}}},
			{Path: "b.yml", Services: []compose.Service{{Name: "svc2", CgroupParent: "shared"}}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services")
	}
}
