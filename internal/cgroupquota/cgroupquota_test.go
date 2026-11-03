package cgroupquota

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

func TestNoCPUQuota(t *testing.T) {
	c := collected(compose.Service{Name: "app"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cgroup_no_cpu_quota") {
		t.Error("expected cgroup_no_cpu_quota when no CPU settings")
	}
	if r.Summary.NoCPUQuota != 1 {
		t.Errorf("expected 1 no_cpu_quota, got %d", r.Summary.NoCPUQuota)
	}
}

func TestCPUQuotaWithCpus(t *testing.T) {
	c := collected(compose.Service{Name: "app", CPUs: "0.5"})
	r := Analyze(c)
	if hasRule(r.Services[0], "cgroup_no_cpu_quota") {
		t.Error("should not flag when cpus is set")
	}
}

func TestCPUQuotaWithCpuShares(t *testing.T) {
	c := collected(compose.Service{Name: "app", CpuShares: 512})
	r := Analyze(c)
	if hasRule(r.Services[0], "cgroup_no_cpu_quota") {
		t.Error("should not flag when cpu_shares is set")
	}
}

func TestCPUQuotaWithCpusetCpus(t *testing.T) {
	c := collected(compose.Service{Name: "app", CpusetCpus: "0,1"})
	r := Analyze(c)
	if hasRule(r.Services[0], "cgroup_no_cpu_quota") {
		t.Error("should not flag when cpuset_cpus is set")
	}
}

func TestNoMemLimit(t *testing.T) {
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cgroup_no_mem_limit") {
		t.Error("expected cgroup_no_mem_limit when no mem_limit set")
	}
	if r.Summary.NoMemLimit != 1 {
		t.Errorf("expected 1 no_mem_limit, got %d", r.Summary.NoMemLimit)
	}
}

func TestWithMemLimit(t *testing.T) {
	c := collected(compose.Service{Name: "app", MemLimit: "512m"})
	r := Analyze(c)
	if hasRule(r.Services[0], "cgroup_no_mem_limit") {
		t.Error("should not flag when mem_limit is set")
	}
}

func TestMemRatioImbalance(t *testing.T) {
	c := collected(compose.Service{Name: "app", MemLimit: "8g", MemReservation: "1g"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cgroup_mem_ratio_imbalance") {
		t.Error("expected cgroup_mem_ratio_imbalance when limit > 4x reservation")
	}
	if r.Summary.MemRatioImbalance != 1 {
		t.Errorf("expected 1 mem_ratio_imbalance, got %d", r.Summary.MemRatioImbalance)
	}
}

func TestMemRatioBalanced(t *testing.T) {
	c := collected(compose.Service{Name: "app", MemLimit: "2g", MemReservation: "1g"})
	r := Analyze(c)
	if hasRule(r.Services[0], "cgroup_mem_ratio_imbalance") {
		t.Error("should not flag balanced ratio")
	}
}

func TestMemRatioBoundary(t *testing.T) {
	c := collected(compose.Service{Name: "app", MemLimit: "4g", MemReservation: "1g"})
	r := Analyze(c)
	if hasRule(r.Services[0], "cgroup_mem_ratio_imbalance") {
		t.Error("4x boundary should not be flagged")
	}
}

func TestNoBlkioLimit(t *testing.T) {
	c := collected(compose.Service{Name: "db"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cgroup_no_blkio_limit") {
		t.Error("expected cgroup_no_blkio_limit when no blkio settings")
	}
	if r.Summary.NoBlkioLimit != 1 {
		t.Errorf("expected 1 no_blkio_limit, got %d", r.Summary.NoBlkioLimit)
	}
}

func TestWithBlkioWeight(t *testing.T) {
	c := collected(compose.Service{Name: "db", BlkioWeight: 500})
	r := Analyze(c)
	if hasRule(r.Services[0], "cgroup_no_blkio_limit") {
		t.Error("should not flag when blkio_weight is set")
	}
}

func TestWithDeviceReadBps(t *testing.T) {
	c := collected(compose.Service{Name: "db", BlkioDeviceReadBps: []compose.BlkioRateDevice{{Path: "/dev/sda", Rate: "50m"}}})
	r := Analyze(c)
	if hasRule(r.Services[0], "cgroup_no_blkio_limit") {
		t.Error("should not flag when device_read_bps is set")
	}
}

func TestDeviceAccess(t *testing.T) {
	c := collected(compose.Service{Name: "gpu", Devices: []string{"/dev/nvidia0:/dev/nvidia0"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cgroup_device_access") {
		t.Error("expected cgroup_device_access for device mapping")
	}
	if r.Summary.DeviceAccess != 1 {
		t.Errorf("expected 1 device_access, got %d", r.Summary.DeviceAccess)
	}
}

func TestMultipleDevices(t *testing.T) {
	c := collected(compose.Service{Name: "gpu", Devices: []string{"/dev/nvidia0:/dev/nvidia0", "/dev/dri:/dev/dri"}})
	r := Analyze(c)
	if r.Summary.DeviceAccess != 2 {
		t.Errorf("expected 2 device_access findings, got %d", r.Summary.DeviceAccess)
	}
}

func TestNoDevices(t *testing.T) {
	c := collected(compose.Service{Name: "web", MemLimit: "256m", CPUs: "0.5", BlkioWeight: 300})
	r := Analyze(c)
	if hasRule(r.Services[0], "cgroup_device_access") {
		t.Error("should not flag device_access when no devices mapped")
	}
}

func TestCgroupConflict(t *testing.T) {
	c := collected(compose.Service{Name: "app", CgroupParent: "custom", CgroupNsMode: "private"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cgroup_config_conflict") {
		t.Error("expected cgroup_config_conflict when both cgroup_parent and cgroup ns mode set")
	}
	if r.Summary.CgroupConflict != 1 {
		t.Errorf("expected 1 cgroup_conflict, got %d", r.Summary.CgroupConflict)
	}
}

func TestNoCgroupConflict(t *testing.T) {
	c := collected(compose.Service{Name: "app", CgroupParent: "custom"})
	r := Analyze(c)
	if hasRule(r.Services[0], "cgroup_config_conflict") {
		t.Error("should not flag when only cgroup_parent is set")
	}
}

func TestMultipleServices(t *testing.T) {
	c := collected(
		compose.Service{Name: "web", CPUs: "0.5", MemLimit: "256m", BlkioWeight: 300},
		compose.Service{Name: "db"},
		compose.Service{Name: "gpu", Devices: []string{"/dev/nvidia0:/dev/nvidia0"}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
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
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{Name: "app", Devices: []string{"/dev/nvidia0"}})
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
