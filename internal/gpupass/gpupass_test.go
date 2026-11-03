package gpupass

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

func TestNvidiaDevice(t *testing.T) {
	c := collected(compose.Service{
		Name:    "ml-worker",
		Devices: []string{"/dev/nvidia0"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "gpupass_gpu_device") {
		t.Error("expected gpupass_gpu_device for /dev/nvidia0")
	}
	if r.Summary.GPUDevices != 1 {
		t.Errorf("expected 1 GPU device finding, got %d", r.Summary.GPUDevices)
	}
}

func TestDRIDevice(t *testing.T) {
	c := collected(compose.Service{
		Name:    "render",
		Devices: []string{"/dev/dri/renderD128"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "gpupass_gpu_device") {
		t.Error("expected gpupass_gpu_device for /dev/dri/renderD128")
	}
}

func TestKFDDevice(t *testing.T) {
	c := collected(compose.Service{
		Name:    "amd-worker",
		Devices: []string{"/dev/kfd"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "gpupass_gpu_device") {
		t.Error("expected gpupass_gpu_device for /dev/kfd")
	}
}

func TestBroadDevicePath(t *testing.T) {
	c := collected(compose.Service{
		Name:    "bad",
		Devices: []string{"/dev/dri"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "gpupass_broad_device") {
		t.Error("expected gpupass_broad_device for /dev/dri")
	}
	if r.Summary.BroadDevices != 1 {
		t.Errorf("expected 1 broad device, got %d", r.Summary.BroadDevices)
	}
}

func TestPrivilegedGPU(t *testing.T) {
	c := collected(compose.Service{
		Name:       "dangerous",
		Privileged: true,
		Devices:    []string{"/dev/nvidia0"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "gpupass_privileged_gpu") {
		t.Error("expected gpupass_privileged_gpu for privileged + GPU")
	}
	if r.Summary.PrivilegedGPU != 1 {
		t.Errorf("expected 1 privileged GPU, got %d", r.Summary.PrivilegedGPU)
	}
}

func TestPrivilegedWithoutGPU(t *testing.T) {
	c := collected(compose.Service{
		Name:       "priv-only",
		Privileged: true,
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "gpupass_privileged_gpu") {
		t.Error("should not flag privileged without GPU devices")
	}
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{Name: "clean"})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Services[0].Findings))
	}
}

func TestNonGPUDevice(t *testing.T) {
	c := collected(compose.Service{
		Name:    "usb",
		Devices: []string{"/dev/ttyUSB0"},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for non-GPU device, got %d", len(r.Services[0].Findings))
	}
}

func TestInfinibandDevice(t *testing.T) {
	c := collected(compose.Service{
		Name:    "rdma",
		Devices: []string{"/dev/infiniband/uverbs0"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "gpupass_gpu_device") {
		t.Error("expected gpupass_gpu_device for infiniband device")
	}
}

func TestVFIODevice(t *testing.T) {
	c := collected(compose.Service{
		Name:    "pci-pass",
		Devices: []string{"/dev/vfio/1"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "gpupass_gpu_device") {
		t.Error("expected gpupass_gpu_device for VFIO device")
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
	c := collected(compose.Service{
		Name:    "gpu",
		Devices: []string{"/dev/nvidia0"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{
		Name:    "gpu",
		Devices: []string{"/dev/nvidia0"},
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
		t.Errorf("expected 1 service, got %d", r2.Summary.TotalServices)
	}
}

func TestDeviceWithMapping(t *testing.T) {
	c := collected(compose.Service{
		Name:    "mapped",
		Devices: []string{"/dev/nvidia0:/dev/nvidia0"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "gpupass_gpu_device") {
		t.Error("expected gpupass_gpu_device for mapped nvidia device")
	}
}
