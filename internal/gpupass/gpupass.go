package gpupass

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type ServiceResult struct {
	Service  string    `json:"service"`
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices  int `json:"total_services"`
	TotalFindings  int `json:"total_findings"`
	GPUDevices     int `json:"gpu_devices"`
	BroadDevices   int `json:"broad_devices"`
	PrivilegedGPU  int `json:"privileged_gpu"`
}

var gpuDevicePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^/dev/nvidia\d*$`),
	regexp.MustCompile(`^/dev/nvidiactl$`),
	regexp.MustCompile(`^/dev/nvidia-uvm`),
	regexp.MustCompile(`^/dev/dri/`),
	regexp.MustCompile(`^/dev/kfd$`),
	regexp.MustCompile(`^/dev/infiniband/`),
	regexp.MustCompile(`^/dev/vfio/`),
}

var broadDevicePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^/dev/dri$`),
	regexp.MustCompile(`^/dev$`),
	regexp.MustCompile(`^/dev/nvidia$`),
}

func isGPUDevice(dev string) bool {
	host := strings.SplitN(dev, ":", 2)[0]
	for _, p := range gpuDevicePatterns {
		if p.MatchString(host) {
			return true
		}
	}
	return false
}

func isBroadDevice(dev string) bool {
	host := strings.SplitN(dev, ":", 2)[0]
	for _, p := range broadDevicePatterns {
		if p.MatchString(host) {
			return true
		}
	}
	return false
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, dev := range svc.Devices {
		if isGPUDevice(dev) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "gpupass_gpu_device",
				Message: fmt.Sprintf("Service '%s' mounts GPU device '%s'; GPU passthrough exposes hardware attack surface and may allow DMA-based escapes", svc.Name, dev),
			})
		}

		if isBroadDevice(dev) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "gpupass_broad_device",
				Message: fmt.Sprintf("Service '%s' mounts broad device path '%s'; this exposes all sub-devices and should be restricted to specific device nodes", svc.Name, dev),
			})
		}
	}

	if svc.Privileged && hasAnyGPUDevice(svc.Devices) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "gpupass_privileged_gpu",
			Message: fmt.Sprintf("Service '%s' runs privileged with GPU devices; privileged mode combined with GPU access bypasses all device isolation", svc.Name),
		})
	}

	return sr
}

func hasAnyGPUDevice(devices []string) bool {
	for _, dev := range devices {
		if isGPUDevice(dev) {
			return true
		}
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "gpupass_gpu_device":
				s.GPUDevices++
			case "gpupass_broad_device":
				s.BroadDevices++
			case "gpupass_privileged_gpu":
				s.PrivilegedGPU++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "GPU Passthrough Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  GPU device mounts:    %d\n", r.Summary.GPUDevices)
	fmt.Fprintf(&b, "  Broad device mounts:  %d\n", r.Summary.BroadDevices)
	fmt.Fprintf(&b, "  Privileged + GPU:     %d\n", r.Summary.PrivilegedGPU)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s\n", sr.Service)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		if len(sr.Findings) == 0 {
			fmt.Fprintf(&b, "    (no findings)\n")
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
