package cgroupv2

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
	Name         string    `json:"name"`
	File         string    `json:"file"`
	CgroupV1Keys []string  `json:"cgroup_v1_keys,omitempty"`
	CgroupV2Ready bool     `json:"cgroup_v2_ready"`
	Findings     []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	V2Ready          int `json:"v2_ready"`
	V1Only           int `json:"v1_only"`
	MixedConfig      int `json:"mixed_config"`
	CgroupMounted    int `json:"cgroup_mounted"`
	TotalFindings    int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var v1OnlyKeys = map[string]bool{
	"cpu_shares":         true,
	"cpuset":             true,
	"blkio_weight":       true,
	"device_cgroup_rules": true,
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
		if s.CgroupV2Ready {
			summary.V2Ready++
		}
		for _, f := range s.Findings {
			switch f.RuleID {
			case "cgroupv2_v1_only_key":
				summary.V1Only++
			case "cgroupv2_mixed_config":
				summary.MixedConfig++
			case "cgroupv2_cgroup_mount":
				summary.CgroupMounted++
			}
		}
		summary.TotalFindings += len(s.Findings)
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:          svc.Name,
		File:          file,
		CgroupV2Ready: true,
	}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		if v1OnlyKeys[key] {
			sr.CgroupV1Keys = append(sr.CgroupV1Keys, key)
			sr.CgroupV2Ready = false
		}
	}

	for _, sysctl := range sortedKeys(svc.Sysctls) {
		lower := strings.ToLower(sysctl)
		if strings.HasPrefix(lower, "net.") {
			continue
		}
		if strings.Contains(lower, "cgroup") {
			sr.CgroupV1Keys = append(sr.CgroupV1Keys, "sysctl:"+sysctl)
			sr.CgroupV2Ready = false
		}
	}

	if len(sr.CgroupV1Keys) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "cgroupv2_v1_only_key",
			Severity:    "medium",
			Detail:      fmt.Sprintf("Service uses cgroup v1-only configuration keys: %s", strings.Join(sr.CgroupV1Keys, ", ")),
			Remediation: "Migrate to cgroup v2 equivalents: cpu_shares -> cpu.weight, blkio_weight -> io.weight, cpuset -> cpuset.cpus",
		})
	}

	hasV2 := svc.CPUs != "" || svc.MemLimit != "" || svc.PidsLimit > 0
	if hasV2 && len(sr.CgroupV1Keys) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "cgroupv2_mixed_config",
			Severity:    "high",
			Detail:      "Service mixes cgroup v1 and v2 resource configurations — may behave differently depending on host cgroup mode",
			Remediation: "Standardize on cgroup v2 unified hierarchy; remove v1-only keys",
		})
	}

	for _, vol := range svc.Volumes {
		hostPath := extractHostPath(vol)
		lower := strings.ToLower(hostPath)
		if lower == "/sys/fs/cgroup" || strings.HasPrefix(lower, "/sys/fs/cgroup/") {
			writable := !strings.HasSuffix(vol, ":ro")
			severity := "medium"
			if writable {
				severity = "high"
			}
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "cgroupv2_cgroup_mount",
				Severity:    severity,
				Detail:      fmt.Sprintf("Host cgroup filesystem mounted into container: %s", vol),
				Remediation: "Remove /sys/fs/cgroup mount; if required for monitoring, mount read-only with :ro",
			})
		}
	}

	for _, opt := range svc.SecurityOpt {
		lower := strings.ToLower(opt)
		if strings.Contains(lower, "systempaths=unconfined") {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "cgroupv2_systempaths_unconfined",
				Severity:    "high",
				Detail:      "systempaths=unconfined exposes cgroup filesystem paths that should be masked",
				Remediation: "Remove systempaths=unconfined to keep cgroup paths masked",
			})
		}
	}

	return sr
}

func extractHostPath(vol string) string {
	parts := strings.SplitN(vol, ":", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Cgroup v2 Migration Readiness Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Total services:          %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Cgroup v2 ready:         %d\n", r.Summary.V2Ready)
	fmt.Fprintf(&b, "  V1-only config:          %d\n", r.Summary.V1Only)
	fmt.Fprintf(&b, "  Mixed v1/v2 config:      %d\n", r.Summary.MixedConfig)
	fmt.Fprintf(&b, "  Cgroup mounted:          %d\n", r.Summary.CgroupMounted)
	fmt.Fprintf(&b, "  Total findings:          %d\n\n", r.Summary.TotalFindings)

	for _, s := range r.Services {
		status := "v2-ready"
		if !s.CgroupV2Ready {
			status = "v1-dependent"
		}
		fmt.Fprintf(&b, "  Service: %s (%s) [%s]\n", s.Name, s.File, status)
		if len(s.CgroupV1Keys) > 0 {
			fmt.Fprintf(&b, "    V1 keys: %s\n", strings.Join(s.CgroupV1Keys, ", "))
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Detail)
			fmt.Fprintf(&b, "      Fix: %s\n", f.Remediation)
		}
		if len(s.Findings) > 0 || len(s.CgroupV1Keys) > 0 {
			b.WriteString("\n")
		}
	}

	return b.String()
}
