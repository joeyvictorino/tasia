package readonlyroot

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
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Name     string    `json:"name"`
	File     string    `json:"file"`
	ReadOnly bool      `json:"read_only"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices       int `json:"total_services"`
	WritableRoot        int `json:"writable_root"`
	WritablePrivileged  int `json:"writable_privileged"`
	WritableHostNetwork int `json:"writable_host_network"`
	WritableDangerousCap int `json:"writable_dangerous_cap"`
	WritableDevices     int `json:"writable_devices"`
	TotalFindings       int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var dangerousCaps = map[string]bool{
	"SYS_ADMIN":    true,
	"SYS_PTRACE":   true,
	"DAC_OVERRIDE": true,
	"NET_ADMIN":    true,
	"SYS_RAWIO":    true,
	"MKNOD":        true,
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
		if !s.ReadOnly {
			summary.WritableRoot++
		}
		for _, f := range s.Findings {
			switch f.RuleID {
			case "roroot_writable_privileged":
				summary.WritablePrivileged++
			case "roroot_writable_host_network":
				summary.WritableHostNetwork++
			case "roroot_writable_dangerous_cap":
				summary.WritableDangerousCap++
			case "roroot_writable_devices":
				summary.WritableDevices++
			}
		}
		summary.TotalFindings += len(s.Findings)
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:     svc.Name,
		File:     file,
		ReadOnly: svc.ReadOnly,
	}

	if svc.ReadOnly {
		return sr
	}

	if svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "roroot_writable_privileged",
			Severity:    "critical",
			Detail:      "Writable root filesystem with privileged mode — container can modify host filesystem through bind mounts and device access",
			Remediation: "Add read_only: true or remove privileged: true; use specific capabilities instead of full privilege",
		})
	}

	if strings.EqualFold(svc.NetworkMode, "host") {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "roroot_writable_host_network",
			Severity:    "high",
			Detail:      "Writable root filesystem with host networking — malicious writes can persist network-intercepting tools",
			Remediation: "Add read_only: true to prevent persistent filesystem modifications, or remove network_mode: host",
		})
	}

	for _, cap := range svc.CapAdd {
		upper := strings.ToUpper(cap)
		if upper == "ALL" || dangerousCaps[upper] {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "roroot_writable_dangerous_cap",
				Severity:    "high",
				Detail:      fmt.Sprintf("Writable root filesystem with dangerous capability %s — extends attack surface for persistent compromise", upper),
				Remediation: fmt.Sprintf("Add read_only: true or drop capability %s; use least-privilege capability set", upper),
			})
			break
		}
	}

	if len(svc.Devices) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "roroot_writable_devices",
			Severity:    "high",
			Detail:      fmt.Sprintf("Writable root filesystem with %d device mount(s) — device access combined with writable fs enables persistent exploitation", len(svc.Devices)),
			Remediation: "Add read_only: true to limit impact of device access, or remove unnecessary device mounts",
		})
	}

	return sr
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Read-Only Root Filesystem Compound Risk Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Total services:              %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Writable root filesystem:    %d\n", r.Summary.WritableRoot)
	fmt.Fprintf(&b, "  Writable + privileged:       %d\n", r.Summary.WritablePrivileged)
	fmt.Fprintf(&b, "  Writable + host network:     %d\n", r.Summary.WritableHostNetwork)
	fmt.Fprintf(&b, "  Writable + dangerous caps:   %d\n", r.Summary.WritableDangerousCap)
	fmt.Fprintf(&b, "  Writable + device mounts:    %d\n", r.Summary.WritableDevices)
	fmt.Fprintf(&b, "  Total findings:              %d\n\n", r.Summary.TotalFindings)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		status := "WRITABLE"
		if s.ReadOnly {
			status = "READ-ONLY"
		}
		fmt.Fprintf(&b, "  Service: %s [%s] (%s)\n", s.Name, status, s.File)
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Detail)
			fmt.Fprintf(&b, "      Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}

	return b.String()
}
