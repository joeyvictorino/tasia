package procmount

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
	TotalServices    int `json:"total_services"`
	TotalFindings    int `json:"total_findings"`
	ProcMounts       int `json:"proc_mounts"`
	SysMounts        int `json:"sys_mounts"`
	WritableProcSys  int `json:"writable_proc_sys"`
	CgroupMounts     int `json:"cgroup_mounts"`
	DebugfsMounts    int `json:"debugfs_mounts"`
}

var dangerousPaths = []struct {
	prefix   string
	rule     string
	level    string
	category string
	desc     string
}{
	{"/sys/kernel/debug", "procmount_debugfs", "critical", "debugfs_mounts", "exposes kernel debugging interfaces; can enable arbitrary code execution"},
	{"/sys/fs/cgroup", "procmount_cgroup", "high", "cgroup_mounts", "allows cgroup manipulation for container escape"},
	{"/proc", "procmount_proc", "high", "proc_mounts", "exposes host process information and kernel parameters"},
	{"/sys", "procmount_sys", "high", "sys_mounts", "exposes host kernel subsystem interfaces"},
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

	for _, vol := range svc.Volumes {
		hostPath, _, readOnly := parseVolume(vol)
		hostLower := strings.ToLower(hostPath)

		matched := false
		for _, dp := range dangerousPaths {
			if strings.HasPrefix(hostLower, dp.prefix) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   dp.level,
					Rule:    dp.rule,
					Message: fmt.Sprintf("Service '%s' mounts %s; %s", svc.Name, hostPath, dp.desc),
				})
				matched = true
				break
			}
		}

		if matched && !readOnly {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "procmount_writable",
				Message: fmt.Sprintf("Service '%s' mounts %s as writable; host kernel parameters can be modified", svc.Name, hostPath),
			})
		}
	}

	if svc.Privileged {
		hasDangerousMount := false
		for _, f := range sr.Findings {
			if strings.HasPrefix(f.Rule, "procmount_") && f.Rule != "procmount_writable" {
				hasDangerousMount = true
				break
			}
		}
		if hasDangerousMount {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "procmount_privileged_mount",
				Message: fmt.Sprintf("Service '%s' is privileged with /proc or /sys mounts; full host kernel access", svc.Name),
			})
		}
	}

	return sr
}

func parseVolume(vol string) (hostPath string, containerPath string, readOnly bool) {
	parts := strings.Split(vol, ":")
	if len(parts) >= 2 {
		hostPath = parts[0]
		containerPath = parts[1]
		if len(parts) >= 3 && strings.Contains(parts[2], "ro") {
			readOnly = true
		}
	} else {
		hostPath = vol
		containerPath = vol
	}
	return
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "procmount_proc":
				s.ProcMounts++
			case "procmount_sys":
				s.SysMounts++
			case "procmount_writable":
				s.WritableProcSys++
			case "procmount_cgroup":
				s.CgroupMounts++
			case "procmount_debugfs":
				s.DebugfsMounts++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Proc/Sys Mount Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  /proc mounts:        %d\n", r.Summary.ProcMounts)
	fmt.Fprintf(&b, "  /sys mounts:         %d\n", r.Summary.SysMounts)
	fmt.Fprintf(&b, "  Writable proc/sys:   %d\n", r.Summary.WritableProcSys)
	fmt.Fprintf(&b, "  Cgroup mounts:       %d\n", r.Summary.CgroupMounts)
	fmt.Fprintf(&b, "  Debugfs mounts:      %d\n\n", r.Summary.DebugfsMounts)
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
