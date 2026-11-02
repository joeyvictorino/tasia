package resourcelimits

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
	Category string `json:"category"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type ServiceScore struct {
	Service   string `json:"service"`
	File      string `json:"file"`
	Score     int    `json:"score"`
	Grade     string `json:"grade"`
	MemLimit  string `json:"mem_limit"`
	CPUs      string `json:"cpus"`
	PidsLimit int    `json:"pids_limit"`
	Findings  []Finding `json:"findings"`
}

type Report struct {
	Path     string         `json:"path"`
	Services []ServiceScore `json:"services"`
	Summary  Summary        `json:"summary"`
}

type Summary struct {
	TotalServices int     `json:"total_services"`
	AverageScore  float64 `json:"average_score"`
	Governed      int     `json:"governed"`
	Ungoverned    int     `json:"ungoverned"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			ss := scoreService(svc, cf.Path)
			r.Services = append(r.Services, ss)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func scoreService(svc compose.Service, file string) ServiceScore {
	ss := ServiceScore{
		Service:   svc.Name,
		File:      file,
		MemLimit:  svc.MemLimit,
		CPUs:      svc.CPUs,
		PidsLimit: svc.PidsLimit,
	}

	total := 0
	earned := 0

	// Memory limit set (25 points)
	total += 25
	if svc.MemLimit != "" {
		earned += 25
		if isOverlyGenerous(svc.MemLimit, 8*1024*1024*1024) {
			earned -= 10
			ss.Findings = append(ss.Findings, Finding{
				Service: svc.Name, File: file, Category: "memory",
				Severity: "medium",
				Message:  fmt.Sprintf("Memory limit %s exceeds 8GB; consider tightening", svc.MemLimit),
			})
		}
	} else {
		ss.Findings = append(ss.Findings, Finding{
			Service: svc.Name, File: file, Category: "memory",
			Severity: "high",
			Message:  "No memory limit set; container can consume all host memory",
		})
	}

	// CPU limit set (25 points)
	total += 25
	if svc.CPUs != "" {
		earned += 25
		if cpuVal, err := strconv.ParseFloat(svc.CPUs, 64); err == nil && cpuVal > 4.0 {
			earned -= 10
			ss.Findings = append(ss.Findings, Finding{
				Service: svc.Name, File: file, Category: "cpu",
				Severity: "medium",
				Message:  fmt.Sprintf("CPU limit %.1f exceeds 4 CPUs; consider tightening", cpuVal),
			})
		}
	} else {
		ss.Findings = append(ss.Findings, Finding{
			Service: svc.Name, File: file, Category: "cpu",
			Severity: "high",
			Message:  "No CPU limit set; container can consume all host CPUs",
		})
	}

	// Memory reservation (20 points)
	total += 20
	if svc.MemReservation != "" {
		earned += 20
	} else {
		ss.Findings = append(ss.Findings, Finding{
			Service: svc.Name, File: file, Category: "memory",
			Severity: "low",
			Message:  "No memory reservation set; scheduler cannot guarantee resources",
		})
	}

	// Pids limit (15 points)
	total += 15
	if svc.PidsLimit > 0 {
		earned += 15
	} else {
		ss.Findings = append(ss.Findings, Finding{
			Service: svc.Name, File: file, Category: "pids",
			Severity: "medium",
			Message:  "No pids_limit set; fork bomb could exhaust host PIDs",
		})
	}

	// Read-only rootfs (15 points)
	total += 15
	if svc.ReadOnly {
		earned += 15
	} else {
		ss.Findings = append(ss.Findings, Finding{
			Service: svc.Name, File: file, Category: "filesystem",
			Severity: "low",
			Message:  "Root filesystem is writable; consider read_only: true",
		})
	}

	if total > 0 {
		ss.Score = clamp((earned * 100) / total, 0, 100)
	}
	ss.Grade = gradeFromScore(ss.Score)
	return ss
}

func isOverlyGenerous(memStr string, thresholdBytes int64) bool {
	bytes := parseMemoryBytes(memStr)
	return bytes > thresholdBytes
}

func parseMemoryBytes(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	multiplier := int64(1)
	upper := strings.ToUpper(s)
	if strings.HasSuffix(upper, "G") || strings.HasSuffix(upper, "GB") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimRight(upper, "GB")
	} else if strings.HasSuffix(upper, "M") || strings.HasSuffix(upper, "MB") {
		multiplier = 1024 * 1024
		s = strings.TrimRight(upper, "MB")
	} else if strings.HasSuffix(upper, "K") || strings.HasSuffix(upper, "KB") {
		multiplier = 1024
		s = strings.TrimRight(upper, "KB")
	} else if strings.HasSuffix(upper, "B") {
		s = strings.TrimSuffix(upper, "B")
	}
	s = strings.TrimSpace(s)
	if val, err := strconv.ParseFloat(s, 64); err == nil {
		return int64(val * float64(multiplier))
	}
	return 0
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func gradeFromScore(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func summarize(services []ServiceScore) Summary {
	s := Summary{TotalServices: len(services)}
	if len(services) == 0 {
		return s
	}
	total := 0
	for _, svc := range services {
		total += svc.Score
		if svc.Score >= 60 {
			s.Governed++
		} else {
			s.Ungoverned++
		}
	}
	s.AverageScore = float64(total) / float64(len(services))
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Resource Limits Audit (%d services, avg score %.0f/100, %d governed, %d ungoverned)\n\n",
		r.Summary.TotalServices, r.Summary.AverageScore, r.Summary.Governed, r.Summary.Ungoverned)
	for _, svc := range r.Services {
		mem := svc.MemLimit
		if mem == "" {
			mem = "(none)"
		}
		cpus := svc.CPUs
		if cpus == "" {
			cpus = "(none)"
		}
		fmt.Fprintf(&b, "  %-30s Score: %d/100 [%s]  mem: %s  cpus: %s  pids: %d\n",
			svc.Service, svc.Score, svc.Grade, mem, cpus, svc.PidsLimit)
		fmt.Fprintf(&b, "    file: %s\n", svc.File)
		for _, f := range svc.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.Category, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
