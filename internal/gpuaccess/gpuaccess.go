package gpuaccess

import (
	"fmt"
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
	TotalServices        int `json:"total_services"`
	TotalFindings        int `json:"total_findings"`
	UnrestrictedGPU      int `json:"unrestricted_gpu"`
	MissingGPULimits     int `json:"missing_gpu_limits"`
	SharedGPUDevices     int `json:"shared_gpu_devices"`
	InsecureRuntimeFlags int `json:"insecure_runtime_flags"`
}

var gpuDevicePaths = []string{
	"/dev/nvidia", "/dev/dri", "/dev/kfd",
	"/dev/nvidia0", "/dev/nvidia1", "/dev/nvidia2", "/dev/nvidia3",
	"/dev/nvidiactl", "/dev/nvidia-uvm", "/dev/nvidia-modeset",
	"/dev/dri/card0", "/dev/dri/renderD128",
}

var unsafeRuntimeEnvVars = []string{
	"NVIDIA_VISIBLE_DEVICES=all",
	"NVIDIA_DRIVER_CAPABILITIES=all",
	"CUDA_VISIBLE_DEVICES=all",
}

func isGPUDevice(path string) bool {
	path = strings.TrimSuffix(path, "/")
	for _, g := range gpuDevicePaths {
		if path == g || strings.HasPrefix(path, g+"/") {
			return true
		}
	}
	if strings.HasPrefix(path, "/dev/nvidia") || strings.HasPrefix(path, "/dev/dri/") {
		return true
	}
	return false
}

func hasGPURuntime(svc compose.Service) bool {
	runtime := strings.ToLower(svc.Runtime)
	return runtime == "nvidia" || strings.Contains(runtime, "nvidia")
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}

	gpuServiceUsage := buildGPUDeviceUsage(c)

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, gpuServiceUsage)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func buildGPUDeviceUsage(c *collect.Collected) map[string][]string {
	usage := make(map[string][]string)
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			for _, d := range svc.Devices {
				parts := strings.Split(d, ":")
				hostDev := parts[0]
				if isGPUDevice(hostDev) {
					usage[hostDev] = append(usage[hostDev], svc.Name)
				}
			}
			for _, v := range svc.Volumes {
				parts := strings.Split(v, ":")
				if len(parts) < 2 {
					continue
				}
				if isGPUDevice(parts[0]) {
					usage[parts[0]] = append(usage[parts[0]], svc.Name)
				}
			}
		}
	}
	return usage
}

func analyzeService(svc compose.Service, file string, gpuUsage map[string][]string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, d := range svc.Devices {
		parts := strings.Split(d, ":")
		hostDev := parts[0]
		if !isGPUDevice(hostDev) {
			continue
		}

		if hostDev == "/dev/nvidia" || hostDev == "/dev/dri" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "unrestricted_gpu_device",
				Message: fmt.Sprintf("Service '%s' maps entire GPU device directory '%s'; expose only specific device nodes to limit GPU access", svc.Name, hostDev),
			})
		}

		if users, ok := gpuUsage[hostDev]; ok && len(users) > 1 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "shared_gpu_device",
				Message: fmt.Sprintf("Service '%s' shares GPU device '%s' with %s; shared GPU access enables side-channel attacks and resource contention", svc.Name, hostDev, formatServiceList(users, svc.Name)),
			})
		}

		if len(parts) >= 3 {
			opts := strings.Split(parts[2], ",")
			if hasOption(opts, "rwm") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "gpu_device_rwm",
					Message: fmt.Sprintf("Service '%s' has read-write-mknod access to GPU device '%s'; restrict to read-only where possible", svc.Name, hostDev),
				})
			}
		}
	}

	for _, v := range svc.Volumes {
		parts := strings.Split(v, ":")
		if len(parts) < 2 {
			continue
		}
		if isGPUDevice(parts[0]) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "gpu_volume_mount",
				Message: fmt.Sprintf("Service '%s' mounts GPU device '%s' as volume at '%s'; use devices directive instead for proper cgroup enforcement", svc.Name, parts[0], parts[1]),
			})
		}
	}

	for _, env := range svc.Environment {
		envLower := strings.ToLower(env)
		for _, unsafe := range unsafeRuntimeEnvVars {
			if strings.ToLower(env) == strings.ToLower(unsafe) || strings.Contains(envLower, strings.ToLower(unsafe)) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "unrestricted_gpu_env",
					Message: fmt.Sprintf("Service '%s' sets '%s'; restrict visible devices/capabilities to minimum required", svc.Name, env),
				})
				break
			}
		}
	}

	if hasGPURuntime(svc) {
		hasGPULimits := false
		for _, env := range svc.Environment {
			upper := strings.ToUpper(env)
			if strings.HasPrefix(upper, "NVIDIA_VISIBLE_DEVICES=") && !strings.Contains(upper, "=ALL") {
				hasGPULimits = true
			}
		}
		if !hasGPULimits {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "missing_gpu_limits",
				Message: fmt.Sprintf("Service '%s' uses nvidia runtime without restricting NVIDIA_VISIBLE_DEVICES; all GPUs are accessible by default", svc.Name),
			})
		}
	}

	return sr
}

func hasOption(opts []string, name string) bool {
	for _, o := range opts {
		if strings.TrimSpace(o) == name {
			return true
		}
	}
	return false
}

func formatServiceList(services []string, exclude string) string {
	var others []string
	for _, s := range services {
		if s != exclude {
			others = append(others, "'"+s+"'")
		}
	}
	if len(others) == 0 {
		return "other services"
	}
	return strings.Join(others, ", ")
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "unrestricted_gpu_device", "gpu_volume_mount":
				s.UnrestrictedGPU++
			case "missing_gpu_limits":
				s.MissingGPULimits++
			case "shared_gpu_device":
				s.SharedGPUDevices++
			case "unrestricted_gpu_env", "gpu_device_rwm":
				s.InsecureRuntimeFlags++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "GPU Access Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Unrestricted GPU access: %d\n", r.Summary.UnrestrictedGPU)
	fmt.Fprintf(&b, "  Missing GPU limits:      %d\n", r.Summary.MissingGPULimits)
	fmt.Fprintf(&b, "  Shared GPU devices:      %d\n", r.Summary.SharedGPUDevices)
	fmt.Fprintf(&b, "  Insecure runtime flags:  %d\n\n", r.Summary.InsecureRuntimeFlags)
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
