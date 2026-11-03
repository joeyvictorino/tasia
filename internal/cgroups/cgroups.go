package cgroups

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Detail   string `json:"detail"`
}

type ServiceResult struct {
	Name     string    `json:"name"`
	File     string    `json:"file"`
	MemLimit string    `json:"mem_limit,omitempty"`
	CPUs     string    `json:"cpus,omitempty"`
	PidsLimit int      `json:"pids_limit,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
	Score    int       `json:"score"`
	Grade    string    `json:"grade"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	WithLimits       int `json:"with_limits"`
	WithoutMemLimit  int `json:"without_mem_limit"`
	WithoutCPULimit  int `json:"without_cpu_limit"`
	WithoutPidsLimit int `json:"without_pids_limit"`
	TotalFindings    int `json:"total_findings"`
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
		hasAny := false
		if s.MemLimit != "" || s.CPUs != "" || s.PidsLimit > 0 {
			hasAny = true
		}
		if hasAny {
			summary.WithLimits++
		}
		if s.MemLimit == "" {
			summary.WithoutMemLimit++
		}
		if s.CPUs == "" {
			summary.WithoutCPULimit++
		}
		if s.PidsLimit == 0 {
			summary.WithoutPidsLimit++
		}
		summary.TotalFindings += len(s.Findings)
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:      svc.Name,
		File:      file,
		MemLimit:  svc.MemLimit,
		CPUs:      svc.CPUs,
		PidsLimit: svc.PidsLimit,
		Score:     100,
	}

	if svc.MemLimit == "" {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     file,
			Severity: "high",
			Category: "no_memory_limit",
			Detail:   "No memory limit set; container can consume all host memory",
		})
		sr.Score -= 25
	} else {
		bytes := parseMemoryBytes(svc.MemLimit)
		if bytes > 0 && bytes > 8*1024*1024*1024 {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "medium",
				Category: "high_memory_limit",
				Detail:   fmt.Sprintf("Memory limit %s exceeds 8GB; may be excessively permissive", svc.MemLimit),
			})
			sr.Score -= 10
		}
	}

	if svc.MemReservation != "" && svc.MemLimit != "" {
		res := parseMemoryBytes(svc.MemReservation)
		lim := parseMemoryBytes(svc.MemLimit)
		if res > 0 && lim > 0 && res > lim {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "medium",
				Category: "reservation_exceeds_limit",
				Detail:   fmt.Sprintf("Memory reservation %s exceeds limit %s", svc.MemReservation, svc.MemLimit),
			})
			sr.Score -= 15
		}
	}

	if svc.CPUs == "" {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     file,
			Severity: "medium",
			Category: "no_cpu_limit",
			Detail:   "No CPU limit set; container can use all host CPU cores",
		})
		sr.Score -= 15
	} else {
		cpuVal, err := strconv.ParseFloat(svc.CPUs, 64)
		if err == nil && cpuVal > 8 {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "low",
				Category: "high_cpu_limit",
				Detail:   fmt.Sprintf("CPU limit %s exceeds 8 cores; may be excessively permissive", svc.CPUs),
			})
			sr.Score -= 5
		}
	}

	if svc.PidsLimit == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     file,
			Severity: "medium",
			Category: "no_pids_limit",
			Detail:   "No PID limit set; fork bomb could exhaust host process table",
		})
		sr.Score -= 15
	}

	if svc.MemLimit == "" && svc.CPUs == "" && svc.PidsLimit == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     file,
			Severity: "high",
			Category: "no_resource_limits",
			Detail:   "No cgroup resource limits configured; container is unbounded",
		})
		sr.Score -= 10
	}

	if sr.Score < 0 {
		sr.Score = 0
	}
	sr.Grade = scoreToGrade(sr.Score)
	return sr
}

func parseMemoryBytes(s string) int64 {
	s = strings.TrimSpace(strings.ToLower(s))
	multipliers := map[string]int64{
		"k": 1024,
		"m": 1024 * 1024,
		"g": 1024 * 1024 * 1024,
		"t": 1024 * 1024 * 1024 * 1024,
		"kb": 1024,
		"mb": 1024 * 1024,
		"gb": 1024 * 1024 * 1024,
		"tb": 1024 * 1024 * 1024 * 1024,
	}
	for suffix, mult := range multipliers {
		if strings.HasSuffix(s, suffix) {
			numStr := strings.TrimSuffix(s, suffix)
			if val, err := strconv.ParseFloat(numStr, 64); err == nil {
				return int64(val * float64(mult))
			}
		}
	}
	if val, err := strconv.ParseInt(s, 10, 64); err == nil {
		return val
	}
	return 0
}

func scoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Cgroup Resource Limits Audit (%d services, %d with limits, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.WithLimits, r.Summary.TotalFindings)

	fmt.Fprintf(&b, "  Without memory limit: %d\n", r.Summary.WithoutMemLimit)
	fmt.Fprintf(&b, "  Without CPU limit:    %d\n", r.Summary.WithoutCPULimit)
	fmt.Fprintf(&b, "  Without PID limit:    %d\n\n", r.Summary.WithoutPidsLimit)

	for _, s := range r.Services {
		fmt.Fprintf(&b, "  %-30s [%s] score=%d\n", s.Name, s.Grade, s.Score)
		if s.MemLimit != "" {
			fmt.Fprintf(&b, "    mem_limit: %s\n", s.MemLimit)
		}
		if s.CPUs != "" {
			fmt.Fprintf(&b, "    cpus: %s\n", s.CPUs)
		}
		if s.PidsLimit > 0 {
			fmt.Fprintf(&b, "    pids_limit: %d\n", s.PidsLimit)
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.Category, f.Detail)
		}
		b.WriteString("\n")
	}
	return b.String()
}
