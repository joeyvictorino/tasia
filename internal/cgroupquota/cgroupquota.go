package cgroupquota

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
	NoCPUQuota        int `json:"no_cpu_quota"`
	NoMemLimit        int `json:"no_mem_limit"`
	MemRatioImbalance int `json:"mem_ratio_imbalance"`
	NoBlkioLimit      int `json:"no_blkio_limit"`
	DeviceAccess      int `json:"device_access"`
	CgroupConflict    int `json:"cgroup_conflict"`
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

	if svc.CPUs == "" && svc.CpuShares == 0 && svc.CpusetCpus == "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cgroup_no_cpu_quota",
			Message: fmt.Sprintf("Service '%s' has no CPU quota (cpus, cpu_shares, or cpuset); can consume unlimited CPU", svc.Name),
		})
	}

	if svc.MemLimit == "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "cgroup_no_mem_limit",
			Message: fmt.Sprintf("Service '%s' has no mem_limit; can consume all available host memory", svc.Name),
		})
	}

	if svc.MemLimit != "" && svc.MemReservation != "" {
		limit := parseSize(svc.MemLimit)
		reservation := parseSize(svc.MemReservation)
		if reservation > 0 && limit > 0 && limit > reservation*4 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "cgroup_mem_ratio_imbalance",
				Message: fmt.Sprintf("Service '%s' mem_limit (%s) exceeds mem_reservation (%s) by more than 4x; reservation may be ineffective", svc.Name, svc.MemLimit, svc.MemReservation),
			})
		}
	}

	if svc.BlkioWeight == 0 && len(svc.BlkioDeviceReadBps) == 0 && len(svc.BlkioDeviceWriteBps) == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "cgroup_no_blkio_limit",
			Message: fmt.Sprintf("Service '%s' has no block IO limits (blkio_weight, device_read_bps, device_write_bps); IO contention possible", svc.Name),
		})
	}

	if len(svc.Devices) > 0 {
		for _, dev := range svc.Devices {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "cgroup_device_access",
				Message: fmt.Sprintf("Service '%s' has device mapping '%s'; grants direct device access bypassing cgroup device controller", svc.Name, dev),
			})
		}
	}

	if svc.CgroupParent != "" && svc.CgroupNsMode != "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cgroup_config_conflict",
			Message: fmt.Sprintf("Service '%s' sets both cgroup_parent (%s) and cgroup namespace mode (%s); potential configuration conflict", svc.Name, svc.CgroupParent, svc.CgroupNsMode),
		})
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
			case "cgroup_no_cpu_quota":
				s.NoCPUQuota++
			case "cgroup_no_mem_limit":
				s.NoMemLimit++
			case "cgroup_mem_ratio_imbalance":
				s.MemRatioImbalance++
			case "cgroup_no_blkio_limit":
				s.NoBlkioLimit++
			case "cgroup_device_access":
				s.DeviceAccess++
			case "cgroup_config_conflict":
				s.CgroupConflict++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Cgroup Quota Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No CPU quota:         %d\n", r.Summary.NoCPUQuota)
	fmt.Fprintf(&b, "  No memory limit:      %d\n", r.Summary.NoMemLimit)
	fmt.Fprintf(&b, "  Memory ratio issue:   %d\n", r.Summary.MemRatioImbalance)
	fmt.Fprintf(&b, "  No block IO limit:    %d\n", r.Summary.NoBlkioLimit)
	fmt.Fprintf(&b, "  Device access:        %d\n", r.Summary.DeviceAccess)
	fmt.Fprintf(&b, "  Cgroup conflict:      %d\n\n", r.Summary.CgroupConflict)
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
