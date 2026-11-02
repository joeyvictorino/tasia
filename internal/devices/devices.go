package devices

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service     string `json:"service"`
	File        string `json:"file"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	DevicePath  string `json:"device_path"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Name     string   `json:"name"`
	File     string   `json:"file"`
	Devices  []string `json:"devices,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices       int `json:"total_services"`
	ServicesWithDevices  int `json:"services_with_devices"`
	TotalDeviceMounts   int `json:"total_device_mounts"`
	SensitiveDevices    int `json:"sensitive_devices"`
	GPUDevices          int `json:"gpu_devices"`
	TotalFindings       int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type deviceRule struct {
	ruleID      string
	severity    string
	detail      string
	remediation string
}

var sensitiveDevices = map[string]deviceRule{
	"/dev/mem": {
		ruleID:      "device_access_sensitive",
		severity:    "critical",
		detail:      "Access to /dev/mem grants direct read/write to physical memory; container can read host kernel memory",
		remediation: "Remove /dev/mem device mapping; use appropriate kernel APIs instead",
	},
	"/dev/kmsg": {
		ruleID:      "device_access_sensitive",
		severity:    "high",
		detail:      "Access to /dev/kmsg allows reading and writing kernel log messages; may leak sensitive kernel information",
		remediation: "Remove /dev/kmsg device mapping; use Docker logging drivers for container log access",
	},
	"/dev/net/tun": {
		ruleID:      "device_access_sensitive",
		severity:    "medium",
		detail:      "Access to /dev/net/tun allows creation of network tunnels that can bypass network policies",
		remediation: "Remove /dev/net/tun unless the service is a VPN or network tunnel endpoint",
	},
	"/dev/fuse": {
		ruleID:      "device_access_sensitive",
		severity:    "medium",
		detail:      "Access to /dev/fuse allows mounting custom filesystems that could be used to hide malicious files",
		remediation: "Remove /dev/fuse unless the service requires FUSE filesystem support",
	},
	"/dev/kvm": {
		ruleID:      "device_access_sensitive",
		severity:    "high",
		detail:      "Access to /dev/kvm allows running virtual machines inside the container; potential for nested escape attacks",
		remediation: "Remove /dev/kvm unless the service explicitly requires hardware virtualization",
	},
}

var sensitiveDevicePrefixes = []struct {
	prefix string
	rule   deviceRule
}{
	{
		prefix: "/dev/sda",
		rule: deviceRule{
			ruleID:      "device_access_sensitive",
			severity:    "critical",
			detail:      "Raw disk device access allows reading/writing host disk directly, bypassing all filesystem permissions",
			remediation: "Remove raw disk device mappings; use volume mounts for data access",
		},
	},
	{
		prefix: "/dev/sd",
		rule: deviceRule{
			ruleID:      "device_access_sensitive",
			severity:    "critical",
			detail:      "Raw disk device access allows reading/writing host disk directly, bypassing all filesystem permissions",
			remediation: "Remove raw disk device mappings; use volume mounts for data access",
		},
	},
	{
		prefix: "/dev/nvme",
		rule: deviceRule{
			ruleID:      "device_access_sensitive",
			severity:    "critical",
			detail:      "Raw NVMe device access allows reading/writing host disk directly, bypassing all filesystem permissions",
			remediation: "Remove raw NVMe device mappings; use volume mounts for data access",
		},
	},
}

var gpuDevicePrefixes = []struct {
	prefix string
	detail string
}{
	{prefix: "/dev/nvidia", detail: "NVIDIA GPU device access detected"},
	{prefix: "/dev/dri/", detail: "DRI (Direct Rendering Infrastructure) GPU device access detected"},
}

func Analyze(collected *collect.Collected) Report {
	var services []ServiceResult

	for _, cf := range collected.ComposeFiles {
		for i := range cf.Services {
			sr := analyzeService(&cf.Services[i], cf.Path)
			services = append(services, sr)
		}
	}

	summary := Summary{TotalServices: len(services)}
	for _, s := range services {
		if len(s.Devices) > 0 {
			summary.ServicesWithDevices++
			summary.TotalDeviceMounts += len(s.Devices)
		}
		for _, f := range s.Findings {
			summary.TotalFindings++
			switch f.RuleID {
			case "device_access_sensitive":
				summary.SensitiveDevices++
			case "device_access_gpu":
				summary.GPUDevices++
			}
		}
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:    svc.Name,
		File:    file,
		Devices: svc.Devices,
	}

	for _, dev := range svc.Devices {
		hostDevice := extractHostDevice(dev)
		if hostDevice == "" {
			continue
		}

		if rule, ok := sensitiveDevices[hostDevice]; ok {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      rule.ruleID,
				Severity:    rule.severity,
				DevicePath:  hostDevice,
				Detail:      rule.detail,
				Remediation: rule.remediation,
			})
			continue
		}

		matched := false
		for _, sp := range sensitiveDevicePrefixes {
			if strings.HasPrefix(hostDevice, sp.prefix) {
				sr.Findings = append(sr.Findings, Finding{
					Service:     svc.Name,
					File:        file,
					RuleID:      sp.rule.ruleID,
					Severity:    sp.rule.severity,
					DevicePath:  hostDevice,
					Detail:      sp.rule.detail,
					Remediation: sp.rule.remediation,
				})
				matched = true
				break
			}
		}
		if matched {
			continue
		}

		for _, gp := range gpuDevicePrefixes {
			if strings.HasPrefix(hostDevice, gp.prefix) {
				sr.Findings = append(sr.Findings, Finding{
					Service:     svc.Name,
					File:        file,
					RuleID:      "device_access_gpu",
					Severity:    "info",
					DevicePath:  hostDevice,
					Detail:      gp.detail,
					Remediation: "Verify GPU access is required for this service; GPU passthrough increases attack surface",
				})
				matched = true
				break
			}
		}
	}

	return sr
}

func extractHostDevice(mapping string) string {
	parts := strings.SplitN(mapping, ":", 2)
	return strings.TrimSpace(parts[0])
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Device Access Audit (%d services, %d with devices, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.ServicesWithDevices, r.Summary.TotalFindings)

	fmt.Fprintf(&b, "  Total device mounts:  %d\n", r.Summary.TotalDeviceMounts)
	fmt.Fprintf(&b, "  Sensitive devices:    %d\n", r.Summary.SensitiveDevices)
	fmt.Fprintf(&b, "  GPU devices:          %d\n\n", r.Summary.GPUDevices)

	for _, s := range r.Services {
		if len(s.Devices) == 0 && len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%s)\n", s.Name, s.File)
		for _, d := range s.Devices {
			fmt.Fprintf(&b, "    device: %s\n", d)
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.DevicePath, f.Detail)
			fmt.Fprintf(&b, "           Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
	return b.String()
}
