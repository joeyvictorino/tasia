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
	CgroupNsMode string   `json:"cgroup_ns_mode,omitempty"`
	CgroupParent string   `json:"cgroup_parent,omitempty"`
	Findings     []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices   int `json:"total_services"`
	HostCgroupNs    int `json:"host_cgroup_ns"`
	CustomParent    int `json:"custom_parent"`
	MissingPrivate  int `json:"missing_private"`
	TotalFindings   int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
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
		for _, f := range s.Findings {
			switch f.RuleID {
			case "cgroupns_host_mode":
				summary.HostCgroupNs++
			case "cgroupns_custom_parent":
				summary.CustomParent++
			case "cgroupns_missing_private":
				summary.MissingPrivate++
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
		CgroupNsMode: svc.CgroupNsMode,
		CgroupParent: svc.CgroupParent,
	}

	if strings.EqualFold(svc.CgroupNsMode, "host") {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name, File: file, RuleID: "cgroupns_host_mode", Severity: "critical",
			Detail:      "Service uses host cgroup namespace — container can see and potentially manipulate host cgroup hierarchy",
			Remediation: "Remove cgroup: host or set cgroup: private to isolate the container's cgroup view",
		})
	}

	if svc.CgroupParent != "" && svc.CgroupParent != "/" {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name, File: file, RuleID: "cgroupns_custom_parent", Severity: "medium",
			Detail:      fmt.Sprintf("Custom cgroup_parent '%s' — non-default cgroup placement may bypass resource accounting", svc.CgroupParent),
			Remediation: "Remove cgroup_parent unless a specific cgroup hierarchy is required; use deploy.resources for limits",
		})
	}

	if svc.CgroupNsMode == "" && isPrivilegedOrElevated(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name, File: file, RuleID: "cgroupns_missing_private", Severity: "high",
			Detail:      "Elevated service has no explicit cgroup namespace mode — may inherit host cgroup namespace depending on daemon defaults",
			Remediation: "Set cgroup: private to ensure the container has its own cgroup namespace view",
		})
	}

	return sr
}

func isPrivilegedOrElevated(svc *compose.Service) bool {
	if svc.Privileged {
		return true
	}
	for _, cap := range svc.CapAdd {
		upper := strings.ToUpper(cap)
		if upper == "ALL" || upper == "SYS_ADMIN" || upper == "SYS_RESOURCE" {
			return true
		}
	}
	return false
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Cgroup Namespace Isolation Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Total services:     %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Host cgroup ns:     %d\n", r.Summary.HostCgroupNs)
	fmt.Fprintf(&b, "  Custom parent:      %d\n", r.Summary.CustomParent)
	fmt.Fprintf(&b, "  Missing private:    %d\n", r.Summary.MissingPrivate)
	fmt.Fprintf(&b, "  Total findings:     %d\n\n", r.Summary.TotalFindings)
	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s (%s)\n", s.Name, s.File)
		if s.CgroupNsMode != "" {
			fmt.Fprintf(&b, "    Cgroup ns mode: %s\n", s.CgroupNsMode)
		}
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
