package cgroupns

import (
	"encoding/json"
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
	Name         string    `json:"name"`
	File         string    `json:"file"`
	CgroupParent string   `json:"cgroup_parent,omitempty"`
	Findings     []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices      int `json:"total_services"`
	CustomCgroupParent int `json:"custom_cgroup_parent"`
	SharedCgroup       int `json:"shared_cgroup"`
	HostCgroup         int `json:"host_cgroup"`
	NoCgroupLimits     int `json:"no_cgroup_limits"`
	TotalFindings      int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func Analyze(collected *collect.Collected) Report {
	var services []ServiceResult
	cgroupGroups := make(map[string][]string)

	for _, cf := range collected.ComposeFiles {
		for i := range cf.Services {
			sr := analyzeService(&cf.Services[i], cf.Path)
			services = append(services, sr)
			if cf.Services[i].CgroupParent != "" {
				cgroupGroups[cf.Services[i].CgroupParent] = append(
					cgroupGroups[cf.Services[i].CgroupParent], cf.Services[i].Name)
			}
		}
	}

	for i := range services {
		if services[i].CgroupParent != "" {
			peers := cgroupGroups[services[i].CgroupParent]
			if len(peers) > 1 {
				services[i].Findings = append(services[i].Findings, Finding{
					Service:     services[i].Name,
					File:        services[i].File,
					RuleID:      "cgroupns_shared_cgroup",
					Severity:    "high",
					Detail:      fmt.Sprintf("Service shares cgroup parent '%s' with %d other service(s) — resource limits and visibility shared", services[i].CgroupParent, len(peers)-1),
					Remediation: "Use separate cgroup parents per service or remove cgroup_parent to use default isolation",
				})
			}
		}
	}

	summary := Summary{TotalServices: len(services)}
	for _, s := range services {
		for _, f := range s.Findings {
			switch f.RuleID {
			case "cgroupns_custom_parent":
				summary.CustomCgroupParent++
			case "cgroupns_shared_cgroup":
				summary.SharedCgroup++
			case "cgroupns_host_cgroup":
				summary.HostCgroup++
			case "cgroupns_no_limits":
				summary.NoCgroupLimits++
			}
		}
		summary.TotalFindings += len(s.Findings)
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:         svc.Name,
		File:         file,
		CgroupParent: svc.CgroupParent,
	}

	if svc.CgroupParent != "" {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "cgroupns_custom_parent",
			Severity:    "medium",
			Detail:      fmt.Sprintf("Service uses custom cgroup_parent '%s' — may bypass default cgroup isolation", svc.CgroupParent),
			Remediation: "Remove cgroup_parent unless explicit cgroup hierarchy placement is required",
		})

		if strings.HasPrefix(svc.CgroupParent, "/") || svc.CgroupParent == "/" {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "cgroupns_host_cgroup",
				Severity:    "critical",
				Detail:      fmt.Sprintf("Service cgroup_parent '%s' targets root cgroup hierarchy — container may access host cgroup resources", svc.CgroupParent),
				Remediation: "Remove cgroup_parent or use a non-root cgroup path to maintain resource isolation",
			})
		}
	}

	hasLimits := svc.MemLimit != "" || svc.CPUs != "" || svc.PidsLimit > 0
	if !hasLimits && !svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "cgroupns_no_limits",
			Severity:    "medium",
			Detail:      "Service has no cgroup resource limits (memory, CPU, PIDs) — unbounded resource consumption possible",
			Remediation: "Set mem_limit, cpus, and/or pids_limit to prevent resource exhaustion attacks",
		})
	}

	return sr
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Cgroup Namespace Isolation Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Total services:         %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Custom cgroup parent:   %d\n", r.Summary.CustomCgroupParent)
	fmt.Fprintf(&b, "  Shared cgroup:          %d\n", r.Summary.SharedCgroup)
	fmt.Fprintf(&b, "  Host cgroup:            %d\n", r.Summary.HostCgroup)
	fmt.Fprintf(&b, "  No cgroup limits:       %d\n", r.Summary.NoCgroupLimits)
	fmt.Fprintf(&b, "  Total findings:         %d\n\n", r.Summary.TotalFindings)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s (%s)\n", s.Name, s.File)
		if s.CgroupParent != "" {
			fmt.Fprintf(&b, "    Cgroup parent: %s\n", s.CgroupParent)
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Detail)
			fmt.Fprintf(&b, "      Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
