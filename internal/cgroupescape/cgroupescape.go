package cgroupescape

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
	TotalServices         int `json:"total_services"`
	TotalFindings         int `json:"total_findings"`
	CgroupFSMounts        int `json:"cgroup_fs_mounts"`
	WritableCgroupMounts  int `json:"writable_cgroup_mounts"`
	ReleaseAgentRisks     int `json:"release_agent_risks"`
	PrivilegedCgroupAccess int `json:"privileged_cgroup_access"`
	CgroupNSSharing       int `json:"cgroup_ns_sharing"`
	UnsafeCgroupPaths     int `json:"unsafe_cgroup_paths"`
}

var cgroupPaths = []string{
	"/sys/fs/cgroup",
	"/proc/cgroups",
	"/proc/1/cgroup",
	"/sys/fs/cgroup/release_agent",
}

var releaseAgentPaths = []string{
	"release_agent",
	"notify_on_release",
	"cgroup.event_control",
}

func isCgroupPath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	for _, cp := range cgroupPaths {
		if path == cp || strings.HasPrefix(path, cp+"/") {
			return true
		}
	}
	return false
}

func hasReleaseAgentRef(s string) bool {
	lower := strings.ToLower(s)
	for _, ra := range releaseAgentPaths {
		if strings.Contains(lower, ra) {
			return true
		}
	}
	return false
}

func containerPath(volumeSpec string) string {
	parts := strings.Split(volumeSpec, ":")
	if len(parts) >= 2 {
		return parts[1]
	}
	return parts[0]
}

func hostPath(volumeSpec string) string {
	parts := strings.Split(volumeSpec, ":")
	return parts[0]
}

func isWritableMount(volumeSpec string) bool {
	parts := strings.Split(volumeSpec, ":")
	if len(parts) < 3 {
		return true
	}
	return !strings.Contains(strings.ToLower(parts[2]), "ro")
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, v := range svc.Volumes {
		cp := containerPath(v)
		hp := hostPath(v)
		writable := isWritableMount(v)

		if isCgroupPath(cp) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "cgroup_fs_mount",
				Message: fmt.Sprintf("Service '%s' mounts cgroup filesystem '%s' at '%s'; this enables cgroup escape attacks", svc.Name, hp, cp),
			})

			if writable {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "critical",
					Rule:    "writable_cgroup_mount",
					Message: fmt.Sprintf("Service '%s' mounts cgroup path '%s' writable; an attacker can modify cgroup settings to escape the container", svc.Name, cp),
				})
			}
		}

		if isCgroupPath(hp) && writable {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "writable_cgroup_mount",
				Message: fmt.Sprintf("Service '%s' bind-mounts host cgroup path '%s' writable into container", svc.Name, hp),
			})
		}

		if hasReleaseAgentRef(cp) || hasReleaseAgentRef(hp) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "release_agent_risk",
				Message: fmt.Sprintf("Service '%s' volume references cgroup release_agent path '%s'; this is a known container escape vector (CVE-2022-0492)", svc.Name, v),
			})
		}
	}

	if svc.Privileged {
		hasCgroupVol := false
		for _, v := range svc.Volumes {
			if isCgroupPath(containerPath(v)) || isCgroupPath(hostPath(v)) {
				hasCgroupVol = true
				break
			}
		}
		if hasCgroupVol {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "privileged_cgroup_access",
				Message: fmt.Sprintf("Service '%s' is privileged AND mounts cgroup paths; this combines to allow trivial container escape via cgroup release_agent", svc.Name),
			})
		} else {
			for _, c := range svc.CapAdd {
				upper := strings.ToUpper(c)
				if upper == "SYS_ADMIN" || upper == "ALL" {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "high",
						Rule:    "privileged_cgroup_access",
						Message: fmt.Sprintf("Service '%s' has %s capability; this grants cgroup manipulation abilities that can be used for container escape", svc.Name, upper),
					})
					break
				}
			}
		}
	} else {
		for _, c := range svc.CapAdd {
			upper := strings.ToUpper(c)
			if upper == "SYS_ADMIN" || upper == "ALL" {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "privileged_cgroup_access",
					Message: fmt.Sprintf("Service '%s' has %s capability; this grants cgroup manipulation abilities that can be used for container escape", svc.Name, upper),
				})
				break
			}
		}
	}

	if svc.CgroupParent != "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cgroup_ns_sharing",
			Message: fmt.Sprintf("Service '%s' sets cgroup_parent to '%s'; custom cgroup parents can weaken isolation boundaries", svc.Name, svc.CgroupParent),
		})
	}

	if strings.Contains(strings.ToLower(svc.PidMode), "host") && svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "cgroup_ns_sharing",
			Message: fmt.Sprintf("Service '%s' uses host PID namespace while privileged; host PID + privileged allows cgroup escape via /proc/1/root", svc.Name),
		})
	}

	for _, cmd := range svc.Command {
		if hasReleaseAgentRef(cmd) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "release_agent_risk",
				Message: fmt.Sprintf("Service '%s' command references cgroup release_agent: '%s'", svc.Name, cmd),
			})
		}
	}
	for _, ep := range svc.Entrypoint {
		if hasReleaseAgentRef(ep) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "release_agent_risk",
				Message: fmt.Sprintf("Service '%s' entrypoint references cgroup release_agent: '%s'", svc.Name, ep),
			})
		}
	}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			if isCgroupPath(parts[1]) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "unsafe_cgroup_path",
					Message: fmt.Sprintf("Service '%s' env var '%s' references cgroup path '%s'", svc.Name, parts[0], parts[1]),
				})
			}
		}
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
			case "cgroup_fs_mount":
				s.CgroupFSMounts++
			case "writable_cgroup_mount":
				s.WritableCgroupMounts++
			case "release_agent_risk":
				s.ReleaseAgentRisks++
			case "privileged_cgroup_access":
				s.PrivilegedCgroupAccess++
			case "cgroup_ns_sharing":
				s.CgroupNSSharing++
			case "unsafe_cgroup_path":
				s.UnsafeCgroupPaths++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Cgroup Escape Risk Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Cgroup FS mounts:          %d\n", r.Summary.CgroupFSMounts)
	fmt.Fprintf(&b, "  Writable cgroup mounts:    %d\n", r.Summary.WritableCgroupMounts)
	fmt.Fprintf(&b, "  Release agent risks:       %d\n", r.Summary.ReleaseAgentRisks)
	fmt.Fprintf(&b, "  Privileged cgroup access:  %d\n", r.Summary.PrivilegedCgroupAccess)
	fmt.Fprintf(&b, "  Cgroup NS sharing:         %d\n", r.Summary.CgroupNSSharing)
	fmt.Fprintf(&b, "  Unsafe cgroup paths:       %d\n\n", r.Summary.UnsafeCgroupPaths)
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
