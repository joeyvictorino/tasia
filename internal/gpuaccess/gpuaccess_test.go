package gpuaccess

import (
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

func svc(name string) compose.Service {
	return compose.Service{Name: name}
}

func TestIsGPUDevice(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/dev/nvidia0", true},
		{"/dev/nvidia1", true},
		{"/dev/nvidiactl", true},
		{"/dev/nvidia-uvm", true},
		{"/dev/dri", true},
		{"/dev/dri/card0", true},
		{"/dev/dri/renderD128", true},
		{"/dev/kfd", true},
		{"/dev/sda", false},
		{"/tmp", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isGPUDevice(tt.path)
		if got != tt.want {
			t.Errorf("isGPUDevice(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestHasGPURuntime(t *testing.T) {
	s := compose.Service{Name: "a", Runtime: "nvidia"}
	if !hasGPURuntime(s) {
		t.Fatal("expected nvidia runtime to be detected")
	}
	s.Runtime = "runc"
	if hasGPURuntime(s) {
		t.Fatal("runc should not be detected as GPU runtime")
	}
	s.Runtime = ""
	if hasGPURuntime(s) {
		t.Fatal("empty runtime should not be GPU")
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyzeNoGPU(t *testing.T) {
	s := svc("web")
	s.Volumes = []string{"/data:/data"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestUnrestrictedGPUDevice(t *testing.T) {
	s := svc("ml")
	s.Devices = []string{"/dev/nvidia:/dev/nvidia"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unrestricted_gpu_device" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected unrestricted_gpu_device finding")
	}
}

func TestUnrestrictedDriDevice(t *testing.T) {
	s := svc("ml")
	s.Devices = []string{"/dev/dri:/dev/dri"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unrestricted_gpu_device" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected unrestricted_gpu_device for /dev/dri")
	}
}

func TestSpecificGPUDeviceOK(t *testing.T) {
	s := svc("ml")
	s.Devices = []string{"/dev/nvidia0:/dev/nvidia0"}
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unrestricted_gpu_device" {
				t.Fatal("specific device should not flag unrestricted_gpu_device")
			}
		}
	}
}

func TestSharedGPUDevice(t *testing.T) {
	s1 := svc("ml1")
	s1.Devices = []string{"/dev/nvidia0:/dev/nvidia0"}
	s2 := svc("ml2")
	s2.Devices = []string{"/dev/nvidia0:/dev/nvidia0"}
	c := collected(s1, s2)
	r := Analyze(c)
	found := 0
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "shared_gpu_device" {
				found++
			}
		}
	}
	if found < 2 {
		t.Fatalf("expected shared_gpu_device on both services, got %d", found)
	}
}

func TestGPUVolumeMountDetected(t *testing.T) {
	s := svc("ml")
	s.Volumes = []string{"/dev/nvidia0:/dev/nvidia0"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "gpu_volume_mount" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected gpu_volume_mount finding for GPU device mounted as volume")
	}
}

func TestUnrestrictedGPUEnv(t *testing.T) {
	s := svc("ml")
	s.Environment = []string{"NVIDIA_VISIBLE_DEVICES=all"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unrestricted_gpu_env" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected unrestricted_gpu_env finding")
	}
}

func TestGPUEnvDriverCapabilities(t *testing.T) {
	s := svc("ml")
	s.Environment = []string{"NVIDIA_DRIVER_CAPABILITIES=all"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unrestricted_gpu_env" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected unrestricted_gpu_env for driver capabilities=all")
	}
}

func TestMissingGPULimitsWithRuntime(t *testing.T) {
	s := svc("ml")
	s.Runtime = "nvidia"
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_gpu_limits" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected missing_gpu_limits for nvidia runtime without NVIDIA_VISIBLE_DEVICES")
	}
}

func TestGPULimitsSetCorrectly(t *testing.T) {
	s := svc("ml")
	s.Runtime = "nvidia"
	s.Environment = []string{"NVIDIA_VISIBLE_DEVICES=0"}
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_gpu_limits" {
				t.Fatal("should not flag missing_gpu_limits when NVIDIA_VISIBLE_DEVICES is restricted")
			}
		}
	}
}

func TestGPUDeviceRWM(t *testing.T) {
	s := svc("ml")
	s.Devices = []string{"/dev/nvidia0:/dev/nvidia0:rwm"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "gpu_device_rwm" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected gpu_device_rwm finding for rwm permission")
	}
}

func TestSummaryCountsCorrect(t *testing.T) {
	s := svc("ml")
	s.Devices = []string{"/dev/nvidia:/dev/nvidia"}
	s.Environment = []string{"NVIDIA_VISIBLE_DEVICES=all"}
	s.Runtime = "nvidia"
	c := collected(s)
	r := Analyze(c)
	if r.Summary.TotalServices != 1 {
		t.Fatalf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings < 2 {
		t.Fatalf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text output")
	}
	if !containsStr(text, "0 findings") {
		t.Fatal("expected 0 findings in text")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	s := svc("ml")
	s.Devices = []string{"/dev/nvidia:/dev/nvidia"}
	c := collected(s)
	r := Analyze(c)
	text := FormatText(r)
	if !containsStr(text, "ml") {
		t.Fatal("expected service name in output")
	}
	if !containsStr(text, "GPU Access") {
		t.Fatal("expected header in output")
	}
}

func TestFormatServiceList(t *testing.T) {
	got := formatServiceList([]string{"a", "b", "c"}, "b")
	if got != "'a', 'c'" {
		t.Fatalf("expected \"'a', 'c'\", got %q", got)
	}
}

func TestFormatServiceListEmpty(t *testing.T) {
	got := formatServiceList([]string{"a"}, "a")
	if got != "other services" {
		t.Fatalf("expected 'other services', got %q", got)
	}
}

func TestHasOption(t *testing.T) {
	if !hasOption([]string{"rwm", "ro"}, "rwm") {
		t.Fatal("expected rwm to be found")
	}
	if hasOption([]string{"ro"}, "rwm") {
		t.Fatal("rwm should not be found")
	}
	if hasOption(nil, "rwm") {
		t.Fatal("nil opts should return false")
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || findSubstr(s, sub))
}

func findSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
