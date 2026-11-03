package shmsize

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
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Name     string    `json:"name"`
	File     string    `json:"file"`
	ShmSize  string    `json:"shm_size,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices int `json:"total_services"`
	LargeShm      int `json:"large_shm"`
	DevShmMount   int `json:"dev_shm_mount"`
	TotalFindings int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
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
			summary.TotalFindings++
			switch f.RuleID {
			case "shm_large":
				summary.LargeShm++
			case "shm_devshm_mount":
				summary.DevShmMount++
			}
		}
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{Name: svc.Name, File: file, ShmSize: svc.ShmSize}

	if svc.ShmSize != "" && isLargeShm(svc.ShmSize) {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "shm_large",
			Severity:    "medium",
			Detail:      fmt.Sprintf("shm_size=%s allocates a large shared memory segment; can enable memory-based attacks or resource exhaustion", svc.ShmSize),
			Remediation: "Reduce shm_size to the minimum needed (e.g. 64m for most ML workloads) or remove if not required",
		})
	}

	for _, v := range svc.Volumes {
		if hasDevShmMount(v) {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "shm_devshm_mount",
				Severity:    "medium",
				Detail:      fmt.Sprintf("Volume mount %q exposes host /dev/shm; processes can use it for covert IPC or to exhaust host memory", v),
				Remediation: "Use shm_size instead of mounting /dev/shm directly, or add size limits via tmpfs options",
			})
			break
		}
	}

	return sr
}

func isLargeShm(size string) bool {
	s := strings.TrimSpace(strings.ToLower(size))
	if strings.HasSuffix(s, "g") || strings.HasSuffix(s, "gb") {
		val := strings.TrimRight(s, "gb")
		if n, err := strconv.ParseFloat(val, 64); err == nil && n >= 1 {
			return true
		}
	}
	if strings.HasSuffix(s, "m") || strings.HasSuffix(s, "mb") {
		val := strings.TrimRight(s, "mb")
		if n, err := strconv.Atoi(val); err == nil && n >= 1024 {
			return true
		}
	}
	return false
}

func hasDevShmMount(vol string) bool {
	parts := strings.SplitN(vol, ":", 2)
	if len(parts) < 2 {
		return false
	}
	src := strings.TrimSpace(parts[0])
	return src == "/dev/shm"
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Shared Memory (shm_size) Audit (%d services, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.TotalFindings)

	fmt.Fprintf(&b, "  Large shm_size (>=1g):  %d\n", r.Summary.LargeShm)
	fmt.Fprintf(&b, "  /dev/shm host mount:    %d\n\n", r.Summary.DevShmMount)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%s)\n", s.Name, s.File)
		if s.ShmSize != "" {
			fmt.Fprintf(&b, "    shm_size: %s\n", s.ShmSize)
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.RuleID, f.Detail)
			fmt.Fprintf(&b, "           Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
	return b.String()
}
