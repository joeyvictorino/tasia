package ipcaudit

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
	HostIPC          int `json:"host_ipc"`
	LargeShmSize     int `json:"large_shm_size"`
	NoShmLimit       int `json:"no_shm_limit"`
	PrivilegedHostIPC int `json:"privileged_host_ipc"`
	ShareableIPC     int `json:"shareable_ipc"`
}

const (
	largeShmThreshold int64 = 2 * 1024 * 1024 * 1024 // 2 GiB
)

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

	ipcLower := strings.ToLower(svc.IpcMode)

	if ipcLower == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "ipc_host_namespace",
			Message: fmt.Sprintf("Service '%s' uses ipc: host; shares IPC namespace with host, enabling shared memory access across containers", svc.Name),
		})
	}

	if strings.HasPrefix(ipcLower, "service:") || strings.HasPrefix(ipcLower, "container:") {
		target := ipcLower[strings.Index(ipcLower, ":")+1:]
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "ipc_shared_namespace",
			Message: fmt.Sprintf("Service '%s' shares IPC namespace with '%s'; inter-container shared memory access possible", svc.Name, target),
		})
	}

	if svc.ShmSize != "" {
		shmBytes := parseSize(svc.ShmSize)
		if shmBytes > largeShmThreshold {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "ipc_large_shm",
				Message: fmt.Sprintf("Service '%s' has shm_size: %s (>2g); large shared memory segments increase attack surface", svc.Name, svc.ShmSize),
			})
		}
	}

	if svc.ShmSize == "" && ipcLower == "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "ipc_no_shm_limit",
			Message: fmt.Sprintf("Service '%s' has no explicit shm_size; defaults to 64m which is usually fine but should be documented", svc.Name),
		})
	}

	if svc.Privileged && ipcLower == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "ipc_privileged_host",
			Message: fmt.Sprintf("Service '%s' is privileged with host IPC; can access and manipulate all host shared memory segments", svc.Name),
		})
	}

	for _, v := range svc.Volumes {
		vLower := strings.ToLower(v)
		if strings.Contains(vLower, "/dev/shm") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "ipc_devshm_mount",
				Message: fmt.Sprintf("Service '%s' mounts /dev/shm from host; bypasses container shared memory isolation", svc.Name),
			})
			break
		}
	}

	return sr
}

func parseSize(s string) int64 {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0
	}
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(s, "g"):
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "m"):
		multiplier = 1024 * 1024
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "k"):
		multiplier = 1024
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "b"):
		s = s[:len(s)-1]
	}
	var n int64
	fmt.Sscanf(s, "%d", &n)
	return n * multiplier
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "ipc_host_namespace":
				s.HostIPC++
			case "ipc_large_shm":
				s.LargeShmSize++
			case "ipc_no_shm_limit":
				s.NoShmLimit++
			case "ipc_privileged_host":
				s.PrivilegedHostIPC++
			case "ipc_shared_namespace":
				s.ShareableIPC++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "IPC Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Host IPC:            %d\n", r.Summary.HostIPC)
	fmt.Fprintf(&b, "  Large shm_size:      %d\n", r.Summary.LargeShmSize)
	fmt.Fprintf(&b, "  No shm limit:        %d\n", r.Summary.NoShmLimit)
	fmt.Fprintf(&b, "  Privileged host IPC: %d\n", r.Summary.PrivilegedHostIPC)
	fmt.Fprintf(&b, "  Shareable IPC:       %d\n\n", r.Summary.ShareableIPC)
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
