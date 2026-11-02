package healthcheck

import (
	"fmt"
	"strings"
	"time"

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
	TotalServices   int     `json:"total_services"`
	WithHealthcheck int     `json:"with_healthcheck"`
	AverageScore    float64 `json:"average_score"`
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
	}

	if svc.Healthcheck == nil {
		sr.Score = 0
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Message: "No healthcheck configured",
		})
		sr.Grade = grade(sr.Score)
		return sr
	}

	hc := svc.Healthcheck

	if hc.Disable {
		sr.Score = 0
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Message: "Healthcheck is disabled",
		})
		sr.Grade = grade(sr.Score)
		return sr
	}

	if len(hc.Test) == 0 {
		sr.Score -= 40
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Message: "Healthcheck has no test command",
		})
	}

	if len(hc.Test) > 0 && hc.Test[0] == "CMD-SHELL" {
		sr.Score -= 10
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Message: "Healthcheck uses CMD-SHELL; prefer CMD exec form for reliability",
		})
	}

	if hc.Interval != "" {
		if d, err := time.ParseDuration(normalizeDuration(hc.Interval)); err == nil && d > 60*time.Second {
			sr.Score -= 15
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Message: fmt.Sprintf("Healthcheck interval %s exceeds 60s", hc.Interval),
			})
		}
	} else {
		sr.Score -= 10
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Message: "No explicit healthcheck interval; using Docker default (30s)",
		})
	}

	if hc.StartPeriod != "" {
		if d, err := time.ParseDuration(normalizeDuration(hc.StartPeriod)); err == nil && d > 120*time.Second {
			sr.Score -= 10
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Message: fmt.Sprintf("Start period %s exceeds 120s; slow failure detection", hc.StartPeriod),
			})
		}
	}

	if hc.Retries == 0 {
		sr.Score -= 10
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Message: "No explicit retries; using Docker default (3)",
		})
	}

	if hc.Timeout == "" {
		sr.Score -= 5
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Message: "No explicit timeout; using Docker default (30s)",
		})
	}

	if sr.Score < 0 {
		sr.Score = 0
	}
	sr.Grade = grade(sr.Score)
	return sr
}

func normalizeDuration(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "s") || strings.HasSuffix(s, "m") || strings.HasSuffix(s, "h") {
		return s
	}
	return s + "s"
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
		if sr.Score > 0 {
			s.WithHealthcheck++
		}
	}
	s.AverageScore = float64(total) / float64(len(services))
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Healthcheck Audit (%d services, %d with healthcheck, avg score %.0f)\n\n",
		r.Summary.TotalServices, r.Summary.WithHealthcheck, r.Summary.AverageScore)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s score: %d/100 [%s]\n", sr.Service, sr.Score, sr.Grade)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
