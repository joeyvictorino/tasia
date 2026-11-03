package confinement

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
	Score    int       `json:"score"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices int     `json:"total_services"`
	TotalFindings int     `json:"total_findings"`
	WeakServices  int     `json:"weak_services"`
	AvgScore      float64 `json:"avg_score"`
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
	score := 0

	if svc.ReadOnly {
		score += 15
	}

	if !svc.Privileged {
		score += 20
	}

	if hasCapDrop(svc) {
		score += 15
	}

	if hasSeccomp(svc) {
		score += 15
	}

	if hasUserNs(svc) {
		score += 10
	}

	if hasResourceLimits(svc) {
		score += 10
	}

	if svc.NetworkMode != "host" {
		score += 15
	}

	sr.Score = score

	if score < 50 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "confinement_weak",
			Message: fmt.Sprintf("Service '%s' confinement score is %d/100 (weak); harden container isolation", svc.Name, score),
		})
	} else if score < 75 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "confinement_moderate",
			Message: fmt.Sprintf("Service '%s' confinement score is %d/100 (moderate); consider additional hardening", svc.Name, score),
		})
	}

	return sr
}

func hasCapDrop(svc compose.Service) bool {
	for _, cap := range svc.CapDrop {
		if strings.ToUpper(cap) == "ALL" {
			return true
		}
	}
	return len(svc.CapDrop) >= 3
}

func hasSeccomp(svc compose.Service) bool {
	for _, o := range svc.SecurityOpt {
		if strings.Contains(strings.ToLower(o), "seccomp") {
			return true
		}
	}
	return false
}

func hasUserNs(svc compose.Service) bool {
	return svc.UsernsMode != "" && strings.ToLower(svc.UsernsMode) != "host"
}

func hasResourceLimits(svc compose.Service) bool {
	return svc.MemLimit != "" || svc.CPUs != "" || svc.MemReservation != ""
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Confinement Scoring (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Weak confinement: %d\n", r.Summary.WeakServices)
	fmt.Fprintf(&b, "  Avg score: %.1f/100\n\n", r.Summary.AvgScore)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s  score: %d/100\n", sr.Service, sr.Score)
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

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	total := 0
	for _, svc := range services {
		s.TotalFindings += len(svc.Findings)
		total += svc.Score
		if svc.Score < 50 {
			s.WeakServices++
		}
	}
	if len(services) > 0 {
		s.AvgScore = float64(total) / float64(len(services))
	}
	return s
}
