package nsenter

import (
	"encoding/json"
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
	TotalServices       int `json:"total_services"`
	TotalFindings       int `json:"total_findings"`
	PidHostRisks        int `json:"pid_host_risks"`
	HostNamespaceShares int `json:"host_namespace_shares"`
	PrivilegedNsenter   int `json:"privileged_nsenter"`
	SysAdminCaps        int `json:"sys_admin_caps"`
}

var nsenterCapabilities = []string{
	"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN",
	"SYS_RAWIO", "SYS_MODULE", "DAC_OVERRIDE",
}

func hasCapability(capList []string, target string) bool {
	for _, c := range capList {
		if strings.EqualFold(strings.TrimSpace(c), target) {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if svc.PidMode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "pid_host_nsenter",
			Message: fmt.Sprintf("Service '%s' uses pid: host; processes can see and signal all host processes, enabling nsenter-style namespace escape", svc.Name),
		})
	}

	if svc.NetworkMode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "network_host_ns",
			Message: fmt.Sprintf("Service '%s' shares host network namespace; can observe and manipulate all host network traffic", svc.Name),
		})
	}

	if svc.IpcMode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "ipc_host_ns",
			Message: fmt.Sprintf("Service '%s' shares host IPC namespace; can access shared memory of other processes", svc.Name),
		})
	}

	if svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "privileged_nsenter",
			Message: fmt.Sprintf("Service '%s' is privileged; has unrestricted access to all namespaces and can use nsenter freely", svc.Name),
		})
	}

	if hasCapability(svc.CapAdd, "SYS_ADMIN") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "cap_sys_admin_ns",
			Message: fmt.Sprintf("Service '%s' has CAP_SYS_ADMIN; can mount filesystems, clone namespaces, and perform nsenter operations", svc.Name),
		})
	}

	if hasCapability(svc.CapAdd, "SYS_PTRACE") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "cap_sys_ptrace_ns",
			Message: fmt.Sprintf("Service '%s' has CAP_SYS_PTRACE; can attach to processes in other namespaces and read their memory", svc.Name),
		})
	}

	if svc.PidMode == "host" && svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "full_nsenter_combo",
			Message: fmt.Sprintf("Service '%s' combines pid:host with privileged mode; this is equivalent to root on the host with full nsenter capability", svc.Name),
		})
	}

	return sr
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

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "pid_host_nsenter":
				s.PidHostRisks++
			case "network_host_ns", "ipc_host_ns":
				s.HostNamespaceShares++
			case "privileged_nsenter", "full_nsenter_combo":
				s.PrivilegedNsenter++
			case "cap_sys_admin_ns", "cap_sys_ptrace_ns":
				s.SysAdminCaps++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Namespace Escape (nsenter) Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  PID host risks:           %d\n", r.Summary.PidHostRisks)
	fmt.Fprintf(&b, "  Host namespace shares:    %d\n", r.Summary.HostNamespaceShares)
	fmt.Fprintf(&b, "  Privileged nsenter:       %d\n", r.Summary.PrivilegedNsenter)
	fmt.Fprintf(&b, "  SYS_ADMIN/PTRACE caps:    %d\n\n", r.Summary.SysAdminCaps)
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

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
