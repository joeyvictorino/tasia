package ipcns

import (
	"encoding/json"
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
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Name     string    `json:"name"`
	File     string    `json:"file"`
	IpcMode  string    `json:"ipc_mode,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices int `json:"total_services"`
	HostIpc       int `json:"host_ipc"`
	SharedIpc     int `json:"shared_ipc"`
	LargeShm      int `json:"large_shm"`
	ShmMount      int `json:"shm_mount"`
	TotalFindings int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

const defaultShmThreshold = 256 * 1024 * 1024

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
			case "ipcns_host_ipc":
				summary.HostIpc++
			case "ipcns_shared_ipc":
				summary.SharedIpc++
			case "ipcns_large_shm":
				summary.LargeShm++
			case "ipcns_shm_mount":
				summary.ShmMount++
			}
		}
		summary.TotalFindings += len(s.Findings)
	}
	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{Name: svc.Name, File: file, IpcMode: svc.IpcMode}
	if strings.EqualFold(svc.IpcMode, "host") {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name, File: file, RuleID: "ipcns_host_ipc", Severity: "critical",
			Detail:      "Service uses host IPC namespace — shared memory segments and semaphores visible to all host processes",
			Remediation: "Remove ipc: host unless IPC sharing with the host is required; use container-scoped IPC namespace",
		})
	} else if strings.HasPrefix(svc.IpcMode, "service:") {
		target := strings.TrimPrefix(svc.IpcMode, "service:")
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name, File: file, RuleID: "ipcns_shared_ipc", Severity: "high",
			Detail:      fmt.Sprintf("Service shares IPC namespace with '%s' — shared memory segments visible across containers", target),
			Remediation: "Isolate IPC namespaces unless shared memory communication is required between these services",
		})
	}
	if svc.ShmSize != "" {
		bytes := parseShmSize(svc.ShmSize)
		if bytes > defaultShmThreshold {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name, File: file, RuleID: "ipcns_large_shm", Severity: "medium",
				Detail:      fmt.Sprintf("Shared memory size set to %s — large SHM allocations increase attack surface", svc.ShmSize),
				Remediation: "Reduce shm_size to the minimum required; default 64MB is sufficient for most workloads",
			})
		}
	}
	for _, vol := range svc.Volumes {
		hostPath := extractHostPath(vol)
		if strings.EqualFold(hostPath, "/dev/shm") || strings.HasPrefix(strings.ToLower(hostPath), "/dev/shm/") {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name, File: file, RuleID: "ipcns_shm_mount", Severity: "high",
				Detail:      fmt.Sprintf("Host /dev/shm mounted into container via '%s' — exposes host shared memory", vol),
				Remediation: "Remove /dev/shm volume mount; use container's own /dev/shm instead",
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

func parseShmSize(s string) int64 {
	s = strings.TrimSpace(strings.ToLower(s))
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(s, "gb") || strings.HasSuffix(s, "g"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimRight(s, "gb")
	case strings.HasSuffix(s, "mb") || strings.HasSuffix(s, "m"):
		multiplier = 1024 * 1024
		s = strings.TrimRight(s, "mb")
	case strings.HasSuffix(s, "kb") || strings.HasSuffix(s, "k"):
		multiplier = 1024
		s = strings.TrimRight(s, "kb")
	case strings.HasSuffix(s, "b"):
		s = strings.TrimSuffix(s, "b")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n * multiplier
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("IPC Namespace Sharing Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Total services:     %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Host IPC:           %d\n", r.Summary.HostIpc)
	fmt.Fprintf(&b, "  Shared IPC:         %d\n", r.Summary.SharedIpc)
	fmt.Fprintf(&b, "  Large SHM:          %d\n", r.Summary.LargeShm)
	fmt.Fprintf(&b, "  /dev/shm mounted:   %d\n", r.Summary.ShmMount)
	fmt.Fprintf(&b, "  Total findings:     %d\n\n", r.Summary.TotalFindings)
	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s (%s)\n", s.Name, s.File)
		if s.IpcMode != "" {
			fmt.Fprintf(&b, "    IPC mode: %s\n", s.IpcMode)
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
