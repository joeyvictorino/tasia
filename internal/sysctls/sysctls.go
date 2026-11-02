package sysctls

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service     string `json:"service"`
	File        string `json:"file"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	SysctlKey   string `json:"sysctl_key"`
	SysctlValue string `json:"sysctl_value"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Name     string            `json:"name"`
	File     string            `json:"file"`
	Sysctls  map[string]string `json:"sysctls,omitempty"`
	Findings []Finding         `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices     int `json:"total_services"`
	ServicesWithSysctls int `json:"services_with_sysctls"`
	TotalSysctls      int `json:"total_sysctls"`
	DangerousSysctls  int `json:"dangerous_sysctls"`
	TotalFindings     int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var dangerousSysctls = map[string]struct {
	severity    string
	detail      string
	remediation string
}{
	"net.ipv4.ip_forward": {
		severity:    "high",
		detail:      "IP forwarding allows the container to route traffic between networks, enabling man-in-the-middle attacks",
		remediation: "Remove net.ipv4.ip_forward unless the service is an intentional router or VPN gateway",
	},
	"net.ipv4.conf.all.forwarding": {
		severity:    "high",
		detail:      "Enables IP forwarding on all interfaces; container can intercept and route host network traffic",
		remediation: "Remove net.ipv4.conf.all.forwarding unless the service requires multi-interface routing",
	},
	"kernel.core_pattern": {
		severity:    "critical",
		detail:      "Overriding kernel.core_pattern can write arbitrary files to the host filesystem via core dumps",
		remediation: "Remove kernel.core_pattern; use the host's default core dump configuration",
	},
}

var thresholdSysctls = map[string]struct {
	maxValue    int64
	severity    string
	detail      string
	remediation string
}{
	"kernel.shmmax": {
		maxValue:    68719476736, // 64GB
		severity:    "medium",
		detail:      "Extremely high shared memory maximum (%s bytes) could enable memory exhaustion attacks",
		remediation: "Set kernel.shmmax to a value appropriate for the workload (typically 32-64MB for most applications)",
	},
	"net.core.somaxconn": {
		maxValue:    65535,
		severity:    "medium",
		detail:      "Maximum socket listen backlog set to %s; extremely high values can waste kernel resources",
		remediation: "Set net.core.somaxconn to a reasonable value (1024-4096 for most applications)",
	},
}

var exactMatchSysctls = map[string]struct {
	matchValue  string
	severity    string
	detail      string
	remediation string
}{
	"vm.overcommit_memory": {
		matchValue:  "1",
		severity:    "medium",
		detail:      "vm.overcommit_memory=1 disables overcommit accounting; kernel always grants allocations which can cause OOM kills",
		remediation: "Use vm.overcommit_memory=0 (default heuristic) or 2 (strict) instead of 1 (always overcommit)",
	},
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
		if len(s.Sysctls) > 0 {
			summary.ServicesWithSysctls++
			summary.TotalSysctls += len(s.Sysctls)
		}
		summary.TotalFindings += len(s.Findings)
		for _, f := range s.Findings {
			if f.RuleID == "sysctl_dangerous" {
				summary.DangerousSysctls++
			}
		}
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:    svc.Name,
		File:    file,
		Sysctls: svc.Sysctls,
	}

	for key, val := range svc.Sysctls {
		if info, ok := dangerousSysctls[key]; ok {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "sysctl_dangerous",
				Severity:    info.severity,
				SysctlKey:   key,
				SysctlValue: val,
				Detail:      info.detail,
				Remediation: info.remediation,
			})
			continue
		}

		if info, ok := thresholdSysctls[key]; ok {
			numVal, err := strconv.ParseInt(val, 10, 64)
			if err == nil && numVal > info.maxValue {
				sr.Findings = append(sr.Findings, Finding{
					Service:     svc.Name,
					File:        file,
					RuleID:      "sysctl_dangerous",
					Severity:    info.severity,
					SysctlKey:   key,
					SysctlValue: val,
					Detail:      fmt.Sprintf(info.detail, val),
					Remediation: info.remediation,
				})
			}
			continue
		}

		if info, ok := exactMatchSysctls[key]; ok {
			if val == info.matchValue {
				sr.Findings = append(sr.Findings, Finding{
					Service:     svc.Name,
					File:        file,
					RuleID:      "sysctl_dangerous",
					Severity:    info.severity,
					SysctlKey:   key,
					SysctlValue: val,
					Detail:      info.detail,
					Remediation: info.remediation,
				})
			}
		}
	}

	return sr
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Kernel Sysctl Audit (%d services, %d with sysctls, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.ServicesWithSysctls, r.Summary.TotalFindings)

	fmt.Fprintf(&b, "  Total sysctls configured: %d\n", r.Summary.TotalSysctls)
	fmt.Fprintf(&b, "  Dangerous sysctls:        %d\n\n", r.Summary.DangerousSysctls)

	for _, s := range r.Services {
		if len(s.Sysctls) == 0 && len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%s)\n", s.Name, s.File)
		for k, v := range s.Sysctls {
			fmt.Fprintf(&b, "    %s = %s\n", k, v)
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.SysctlKey, f.Detail)
			fmt.Fprintf(&b, "           Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
	return b.String()
}
