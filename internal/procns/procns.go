package procns

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
	PidMode  string    `json:"pid_mode,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices      int `json:"total_services"`
	HostPidNamespace   int `json:"host_pid_namespace"`
	SharedPidNamespace int `json:"shared_pid_namespace"`
	ProcMounted        int `json:"proc_mounted"`
	SysMounted         int `json:"sys_mounted"`
	TotalFindings      int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var sensitivePaths = []string{
	"/proc", "/sys", "/sys/kernel", "/sys/fs/cgroup",
	"/proc/sysrq-trigger", "/proc/sys", "/proc/kcore",
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
			case "procns_host_pid":
				summary.HostPidNamespace++
			case "procns_shared_pid":
				summary.SharedPidNamespace++
			case "procns_proc_mount":
				summary.ProcMounted++
			case "procns_sys_mount":
				summary.SysMounted++
			}
		}
		summary.TotalFindings += len(s.Findings)
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:    svc.Name,
		File:    file,
		PidMode: svc.PidMode,
	}

	if strings.EqualFold(svc.PidMode, "host") {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "procns_host_pid",
			Severity:    "critical",
			Detail:      "Service uses host PID namespace — can see and signal all host processes",
			Remediation: "Remove pid: host unless process visibility is required; use container-scoped PID namespace",
		})
	} else if strings.HasPrefix(svc.PidMode, "service:") {
		target := strings.TrimPrefix(svc.PidMode, "service:")
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "procns_shared_pid",
			Severity:    "high",
			Detail:      fmt.Sprintf("Service shares PID namespace with '%s' — processes visible across containers", target),
			Remediation: "Isolate PID namespaces unless process coordination is required between these services",
		})
	}

	for _, vol := range svc.Volumes {
		hostPath := extractHostPath(vol)
		lower := strings.ToLower(hostPath)

		if lower == "/proc" || strings.HasPrefix(lower, "/proc/") {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "procns_proc_mount",
				Severity:    "critical",
				Detail:      fmt.Sprintf("Host /proc mounted into container via '%s' — exposes kernel and process information", vol),
				Remediation: "Remove /proc volume mount; use container's own /proc instead",
			})
		}

		if lower == "/sys" || strings.HasPrefix(lower, "/sys/") {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "procns_sys_mount",
				Severity:    "high",
				Detail:      fmt.Sprintf("Host /sys mounted into container via '%s' — exposes kernel subsystem controls", vol),
				Remediation: "Remove /sys volume mount or mount read-only with :ro suffix",
			})
		}
	}

	for _, opt := range svc.SecurityOpt {
		lower := strings.ToLower(opt)
		if strings.Contains(lower, "systempaths=unconfined") {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "procns_systempaths_unconfined",
				Severity:    "high",
				Detail:      "security_opt systempaths=unconfined exposes masked /proc and /sys paths",
				Remediation: "Remove systempaths=unconfined; keep default masked paths for defense in depth",
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

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Process Namespace & /proc Exposure Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Total services:          %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Host PID namespace:      %d\n", r.Summary.HostPidNamespace)
	fmt.Fprintf(&b, "  Shared PID namespace:    %d\n", r.Summary.SharedPidNamespace)
	fmt.Fprintf(&b, "  /proc mounted:           %d\n", r.Summary.ProcMounted)
	fmt.Fprintf(&b, "  /sys mounted:            %d\n", r.Summary.SysMounted)
	fmt.Fprintf(&b, "  Total findings:          %d\n\n", r.Summary.TotalFindings)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s (%s)\n", s.Name, s.File)
		if s.PidMode != "" {
			fmt.Fprintf(&b, "    PID mode: %s\n", s.PidMode)
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Detail)
			fmt.Fprintf(&b, "      Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}

	return b.String()
}
