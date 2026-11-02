package logging

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

type ServiceResult struct {
	Service  string    `json:"service"`
	File     string    `json:"file"`
	Driver   string    `json:"driver"`
	Score    int       `json:"score"`
	Grade    string    `json:"grade"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices    int     `json:"total_services"`
	WithLogDriver    int     `json:"with_log_driver"`
	WithRotation     int     `json:"with_rotation"`
	AverageScore     float64 `json:"average_score"`
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
	sr := ServiceResult{
		Service: svc.Name,
		File:    file,
		Score:   100,
		Driver:  "default",
	}

	if svc.Logging == nil {
		sr.Score -= 20
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Message: "No logging configuration; using Docker default json-file driver",
		})
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Message: "No log rotation limits configured; logs may grow unbounded",
		})
		sr.Score -= 20
		sr.Grade = grade(sr.Score)
		return sr
	}

	lc := svc.Logging
	if lc.Driver != "" {
		sr.Driver = lc.Driver
	}

	if lc.Driver == "none" {
		sr.Score -= 30
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Message: "Logging is disabled (driver: none); no operational visibility",
		})
		sr.Grade = grade(sr.Score)
		return sr
	}

	if lc.Driver == "syslog" {
		addr := lc.Options["syslog-address"]
		if addr != "" && !strings.HasPrefix(addr, "tcp+tls://") && !strings.HasPrefix(addr, "unix://") {
			sr.Score -= 15
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Message: fmt.Sprintf("Syslog address %q may not use TLS; consider tcp+tls://", addr),
			})
		}
	}

	hasMaxSize := false
	hasMaxFile := false
	if ms, ok := lc.Options["max-size"]; ok {
		hasMaxSize = true
		if sizeBytes(ms) > 100*1024*1024 {
			sr.Score -= 10
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Message: fmt.Sprintf("Log max-size %s exceeds 100MB; consider smaller rotation", ms),
			})
		}
	}
	if _, ok := lc.Options["max-file"]; ok {
		hasMaxFile = true
	}

	if !hasMaxSize {
		sr.Score -= 20
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Message: "No max-size log rotation limit configured",
		})
	}
	if !hasMaxFile {
		sr.Score -= 10
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Message: "No max-file log rotation limit configured",
		})
	}

	for _, vol := range svc.Volumes {
		parts := strings.Split(vol, ":")
		if len(parts) >= 2 {
			target := parts[1]
			if strings.HasPrefix(target, "/var/log") || strings.Contains(target, "/logs") {
				isRO := len(parts) >= 3 && parts[2] == "ro"
				if !isRO {
					sr.Score -= 10
					sr.Findings = append(sr.Findings, Finding{
						Level:   "low",
						Message: fmt.Sprintf("Volume mount to %s may bypass log driver; prefer driver-based logging", target),
					})
				}
			}
		}
	}

	if sr.Score < 0 {
		sr.Score = 0
	}
	sr.Grade = grade(sr.Score)
	return sr
}

func sizeBytes(s string) int64 {
	s = strings.TrimSpace(strings.ToLower(s))
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
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n * multiplier
}

func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 50:
		return "C"
	case score >= 25:
		return "D"
	default:
		return "F"
	}
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	if len(services) == 0 {
		return s
	}
	total := 0
	for _, sr := range services {
		total += sr.Score
		if sr.Driver != "default" && sr.Driver != "none" {
			s.WithLogDriver++
		}
		hasRotation := false
		for _, f := range sr.Findings {
			if strings.Contains(f.Message, "max-size") && f.Level == "low" {
				continue
			}
			if strings.Contains(f.Message, "No max-size") || strings.Contains(f.Message, "No log rotation") {
				continue
			}
		}
		if sr.Driver != "default" && sr.Driver != "none" {
			hasSizeIssue := false
			for _, f := range sr.Findings {
				if strings.Contains(f.Message, "No max-size") || strings.Contains(f.Message, "No log rotation") {
					hasSizeIssue = true
				}
			}
			if !hasSizeIssue {
				hasRotation = true
			}
		}
		if hasRotation {
			s.WithRotation++
		}
	}
	s.AverageScore = float64(total) / float64(len(services))
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Logging Audit (%d services, %d with driver, %d with rotation, avg score %.0f)\n\n",
		r.Summary.TotalServices, r.Summary.WithLogDriver, r.Summary.WithRotation, r.Summary.AverageScore)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s driver: %-12s score: %d/100 [%s]\n", sr.Service, sr.Driver, sr.Score, sr.Grade)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
