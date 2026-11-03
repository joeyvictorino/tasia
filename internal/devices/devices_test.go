package devices

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyzeNoDevices(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "web"},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.ServicesWithDevices != 0 {
		t.Fatalf("expected 0 services with devices, got %d", r.Summary.ServicesWithDevices)
	}
}

func TestAnalyzeDevMem(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "exploit", Devices: []string{"/dev/mem:/dev/mem"}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
	f := r.Services[0].Findings[0]
	if f.RuleID != "device_access_sensitive" {
		t.Errorf("expected device_access_sensitive, got %s", f.RuleID)
	}
	if f.Severity != "critical" {
		t.Errorf("expected critical, got %s", f.Severity)
	}
}

func TestAnalyzeDevKmsg(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "logger", Devices: []string{"/dev/kmsg"}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
	if r.Services[0].Findings[0].Severity != "high" {
		t.Errorf("expected high severity, got %s", r.Services[0].Findings[0].Severity)
	}
}

func TestAnalyzeRawDisk(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "backup", Devices: []string{"/dev/sda1:/dev/sda1"}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
	if r.Services[0].Findings[0].Severity != "critical" {
		t.Errorf("expected critical for raw disk, got %s", r.Services[0].Findings[0].Severity)
	}
}

func TestAnalyzeNVMe(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "io", Devices: []string{"/dev/nvme0n1"}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
	if r.Summary.SensitiveDevices != 1 {
		t.Errorf("expected 1 sensitive device, got %d", r.Summary.SensitiveDevices)
	}
}

func TestAnalyzeGPUNvidia(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "ml", Devices: []string{"/dev/nvidia0:/dev/nvidia0"}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
	f := r.Services[0].Findings[0]
	if f.RuleID != "device_access_gpu" {
		t.Errorf("expected device_access_gpu, got %s", f.RuleID)
	}
	if f.Severity != "info" {
		t.Errorf("expected info severity for GPU, got %s", f.Severity)
	}
	if r.Summary.GPUDevices != 1 {
		t.Errorf("expected 1 GPU device, got %d", r.Summary.GPUDevices)
	}
}

func TestAnalyzeGPUDRI(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "render", Devices: []string{"/dev/dri/card0"}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.GPUDevices != 1 {
		t.Errorf("expected 1 GPU device, got %d", r.Summary.GPUDevices)
	}
}

func TestAnalyzeDevNetTun(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "vpn", Devices: []string{"/dev/net/tun"}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
	if r.Services[0].Findings[0].Severity != "medium" {
		t.Errorf("expected medium for /dev/net/tun, got %s", r.Services[0].Findings[0].Severity)
	}
}

func TestAnalyzeMultipleDevices(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "risky", Devices: []string{"/dev/mem", "/dev/sda", "/dev/nvidia0"}},
				{Name: "safe"},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.ServicesWithDevices != 1 {
		t.Fatalf("expected 1 with devices, got %d", r.Summary.ServicesWithDevices)
	}
	if r.Summary.TotalFindings != 3 {
		t.Fatalf("expected 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "dc.yml", Services: []compose.Service{
				{Name: "svc", Devices: []string{"/dev/kvm"}},
			}},
		},
	}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty output")
	}
	if !containsStr(text, "Device Access Audit") {
		t.Error("expected header in output")
	}
	if !containsStr(text, "/dev/kvm") {
		t.Error("expected device path in output")
	}
}

func TestExtractHostDevice(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/dev/sda", "/dev/sda"},
		{"/dev/sda1:/dev/sda1", "/dev/sda1"},
		{"/dev/nvidia0:/dev/nvidia0:rwm", "/dev/nvidia0"},
	}
	for _, tt := range tests {
		got := extractHostDevice(tt.input)
		if got != tt.want {
			t.Errorf("extractHostDevice(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
