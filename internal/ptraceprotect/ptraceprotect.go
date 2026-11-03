package ptraceprotect

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
	TotalServices     int `json:"total_services"`
	TotalFindings     int `json:"total_findings"`
	PtraceEnabled     int `json:"ptrace_enabled"`
	PtracePrivileged  int `json:"ptrace_privileged"`
	DebugCapAdded     int `json:"debug_cap_added"`
	SeccompDisabled   int `json:"seccomp_disabled"`
	ProcessInspection int `json:"process_inspection"`
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

	hasPtrace := hasCapability(svc.CapAdd, "SYS_PTRACE")

	if hasPtrace {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "ptrace_cap_added",
			Message: fmt.Sprintf("Service '%s' has SYS_PTRACE capability; can attach to and debug other processes, inspect memory, and inject code", svc.Name),
		})
	}

	if hasPtrace && svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "ptrace_privileged",
			Message: fmt.Sprintf("Service '%s' is privileged with SYS_PTRACE; can debug host processes and read host process memory", svc.Name),
		})
	}

	if hasPtrace && svc.PidMode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "ptrace_host_pid",
			Message: fmt.Sprintf("Service '%s' has SYS_PTRACE with host PID namespace; can attach to any host process", svc.Name),
		})
	}

	if hasCapability(svc.CapAdd, "SYS_ADMIN") && hasPtrace {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "ptrace_sys_admin",
			Message: fmt.Sprintf("Service '%s' has both SYS_PTRACE and SYS_ADMIN; complete process and namespace control", svc.Name),
		})
	}

	for _, opt := range svc.SecurityOpt {
		lower := strings.ToLower(opt)
		if strings.Contains(lower, "seccomp=unconfined") || strings.Contains(lower, "seccomp:unconfined") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "ptrace_seccomp_off",
				Message: fmt.Sprintf("Service '%s' disables seccomp filtering; ptrace and other dangerous syscalls are unrestricted", svc.Name),
			})
		}
		if strings.Contains(lower, "apparmor=unconfined") || strings.Contains(lower, "apparmor:unconfined") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "ptrace_apparmor_off",
				Message: fmt.Sprintf("Service '%s' disables AppArmor; ptrace restrictions from the default profile are removed", svc.Name),
			})
		}
	}

	for _, vol := range svc.Volumes {
		lower := strings.ToLower(vol)
		if strings.Contains(lower, "/proc") && !strings.Contains(lower, "/proc/") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "ptrace_proc_mount",
				Message: fmt.Sprintf("Service '%s' mounts host /proc; combined with ptrace allows process memory inspection", svc.Name),
			})
		}
	}

	return sr
}

func hasCapability(caps []string, target string) bool {
	for _, c := range caps {
		if strings.EqualFold(strings.TrimSpace(c), target) {
			return true
		}
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		s.TotalFindings += len(sr.Findings)
		for _, f := range sr.Findings {
			switch f.Rule {
			case "ptrace_cap_added":
				s.PtraceEnabled++
			case "ptrace_privileged":
				s.PtracePrivileged++
			case "ptrace_sys_admin":
				s.DebugCapAdded++
			case "ptrace_seccomp_off":
				s.SeccompDisabled++
			case "ptrace_proc_mount":
				s.ProcessInspection++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Ptrace Protection Analysis: %s\n", r.Path)
	b.WriteString(strings.Repeat("=", 50) + "\n\n")

	fmt.Fprintf(&b, "  Services:           %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Findings:           %d\n", r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Ptrace enabled:     %d\n", r.Summary.PtraceEnabled)
	fmt.Fprintf(&b, "  Ptrace privileged:  %d\n", r.Summary.PtracePrivileged)
	fmt.Fprintf(&b, "  Debug cap added:    %d\n", r.Summary.DebugCapAdded)
	fmt.Fprintf(&b, "  Seccomp disabled:   %d\n", r.Summary.SeccompDisabled)
	b.WriteString("\n")

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%s):\n", sr.Service, sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Level, f.Rule, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
