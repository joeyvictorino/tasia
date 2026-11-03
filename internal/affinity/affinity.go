package affinity

import (
	"encoding/json"
	"fmt"
	"strconv"
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
	NoCPULimit        int `json:"no_cpu_limit"`
	NoMemLimit        int `json:"no_mem_limit"`
	HighCPU           int `json:"high_cpu"`
	HighMem           int `json:"high_mem"`
	NoPidsLimit       int `json:"no_pids_limit"`
}

func parseCPUs(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v
}

func parseMemBytes(s string) int64 {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0
	}
	multiplier := int64(1)
	if strings.HasSuffix(s, "g") || strings.HasSuffix(s, "gb") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimRight(s, "gb")
	} else if strings.HasSuffix(s, "m") || strings.HasSuffix(s, "mb") {
		multiplier = 1024 * 1024
		s = strings.TrimRight(s, "mb")
	} else if strings.HasSuffix(s, "k") || strings.HasSuffix(s, "kb") {
		multiplier = 1024
		s = strings.TrimRight(s, "kb")
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0
	}
	return int64(v * float64(multiplier))
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

	cpus := parseCPUs(svc.CPUs)
	if cpus == 0 && svc.CPUs == "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "no_cpu_limit",
			Message: fmt.Sprintf("Service '%s' has no CPU limit; a runaway process can starve other services of CPU time", svc.Name),
		})
	}

	if cpus > 4.0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "high_cpu_allocation",
			Message: fmt.Sprintf("Service '%s' has high CPU allocation (%.1f CPUs); verify this is intentional and not over-provisioned", svc.Name, cpus),
		})
	}

	if svc.MemLimit == "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "no_mem_limit",
			Message: fmt.Sprintf("Service '%s' has no memory limit; a memory leak can exhaust host memory and affect all containers", svc.Name),
		})
	}

	memBytes := parseMemBytes(svc.MemLimit)
	if memBytes > 8*1024*1024*1024 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "high_mem_allocation",
			Message: fmt.Sprintf("Service '%s' has high memory limit (%s); verify this is intentional and not over-provisioned", svc.Name, svc.MemLimit),
		})
	}

	if svc.MemReservation != "" && svc.MemLimit != "" {
		res := parseMemBytes(svc.MemReservation)
		lim := parseMemBytes(svc.MemLimit)
		if res > 0 && lim > 0 && res > lim {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "reservation_exceeds_limit",
				Message: fmt.Sprintf("Service '%s' memory reservation (%s) exceeds limit (%s); reservation should be lower than limit", svc.Name, svc.MemReservation, svc.MemLimit),
			})
		}
	}

	if svc.PidsLimit == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "no_pids_limit",
			Message: fmt.Sprintf("Service '%s' has no PID limit; a fork bomb can exhaust the PID table and affect the host", svc.Name),
		})
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "no_cpu_limit":
				s.NoCPULimit++
			case "no_mem_limit":
				s.NoMemLimit++
			case "high_cpu_allocation":
				s.HighCPU++
			case "high_mem_allocation":
				s.HighMem++
			case "no_pids_limit":
				s.NoPidsLimit++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Resource Affinity & Limits Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No CPU limit:          %d\n", r.Summary.NoCPULimit)
	fmt.Fprintf(&b, "  No memory limit:       %d\n", r.Summary.NoMemLimit)
	fmt.Fprintf(&b, "  High CPU allocation:   %d\n", r.Summary.HighCPU)
	fmt.Fprintf(&b, "  High memory allocation:%d\n", r.Summary.HighMem)
	fmt.Fprintf(&b, "  No PID limit:          %d\n\n", r.Summary.NoPidsLimit)
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
