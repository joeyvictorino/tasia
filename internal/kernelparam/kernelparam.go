package kernelparam

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
	TotalServices      int `json:"total_services"`
	TotalFindings      int `json:"total_findings"`
	DangerousSysctl    int `json:"dangerous_sysctl"`
	NetworkForwarding  int `json:"network_forwarding"`
	KernelCorePath     int `json:"kernel_core_path"`
	PrivilegedSysctl   int `json:"privileged_sysctl"`
	UnrestrictedSysctl int `json:"unrestricted_sysctl"`
	ShmParams          int `json:"shm_params"`
}

var dangerousSysctls = map[string]string{
	"kernel.core_pattern":          "allows writing core dumps to arbitrary paths",
	"kernel.modprobe":              "allows loading arbitrary kernel modules",
	"kernel.panic":                 "can disable panic reboot behavior",
	"kernel.shmmax":                "controls maximum shared memory segment size",
	"kernel.shmall":                "controls total shared memory pages",
	"kernel.shmmni":                "controls maximum shared memory segments",
	"vm.panic_on_oom":              "can disable OOM killer behavior",
	"fs.suid_dumpable":             "can enable core dumps for setuid programs",
	"kernel.randomize_va_space":    "can disable ASLR",
	"kernel.kptr_restrict":         "can expose kernel pointers",
	"kernel.dmesg_restrict":        "can expose kernel log messages",
	"kernel.perf_event_paranoid":   "can allow unprivileged perf events",
	"kernel.unprivileged_bpf_disabled": "can enable unprivileged BPF",
}

var networkForwardingSysctls = map[string]bool{
	"net.ipv4.ip_forward":          true,
	"net.ipv6.conf.all.forwarding": true,
	"net.ipv4.conf.all.forwarding": true,
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

	if len(svc.Sysctls) > 0 {
		for key, val := range svc.Sysctls {
			lower := strings.ToLower(key)

			if reason, ok := dangerousSysctls[lower]; ok {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "kparam_dangerous_sysctl",
					Message: fmt.Sprintf("Service '%s' sets dangerous sysctl '%s=%s'; %s", svc.Name, key, val, reason),
				})
			}

			if networkForwardingSysctls[lower] && (val == "1" || strings.ToLower(val) == "true") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "kparam_network_forwarding",
					Message: fmt.Sprintf("Service '%s' enables IP forwarding via '%s=%s'; container can route traffic between networks", svc.Name, key, val),
				})
			}

			if lower == "kernel.core_pattern" {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "critical",
					Rule:    "kparam_core_pattern",
					Message: fmt.Sprintf("Service '%s' overrides kernel.core_pattern to '%s'; can be used to write arbitrary files on host", svc.Name, val),
				})
			}

			if strings.HasPrefix(lower, "kernel.shm") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "kparam_shm_override",
					Message: fmt.Sprintf("Service '%s' modifies shared memory parameter '%s=%s'; may affect host shared memory limits", svc.Name, key, val),
				})
			}
		}
	}

	if svc.Privileged && len(svc.Sysctls) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "kparam_privileged_sysctl",
			Message: fmt.Sprintf("Service '%s' is privileged with sysctl overrides; privileged containers can modify any kernel parameter", svc.Name),
		})
	}

	if svc.Privileged && len(svc.Sysctls) == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "kparam_unrestricted_privileged",
			Message: fmt.Sprintf("Service '%s' is privileged without explicit sysctl restrictions; has full kernel parameter access", svc.Name),
		})
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "kparam_dangerous_sysctl":
				s.DangerousSysctl++
			case "kparam_network_forwarding":
				s.NetworkForwarding++
			case "kparam_core_pattern":
				s.KernelCorePath++
			case "kparam_privileged_sysctl":
				s.PrivilegedSysctl++
			case "kparam_unrestricted_privileged":
				s.UnrestrictedSysctl++
			case "kparam_shm_override":
				s.ShmParams++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Kernel Parameter Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Dangerous sysctls:      %d\n", r.Summary.DangerousSysctl)
	fmt.Fprintf(&b, "  Network forwarding:     %d\n", r.Summary.NetworkForwarding)
	fmt.Fprintf(&b, "  Core pattern override:  %d\n", r.Summary.KernelCorePath)
	fmt.Fprintf(&b, "  Privileged + sysctl:    %d\n", r.Summary.PrivilegedSysctl)
	fmt.Fprintf(&b, "  Unrestricted privileged:%d\n", r.Summary.UnrestrictedSysctl)
	fmt.Fprintf(&b, "  SHM param overrides:    %d\n\n", r.Summary.ShmParams)
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
