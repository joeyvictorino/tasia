package pidns

import (
	"fmt"
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
	PidMode  string    `json:"pid_mode"`
	Score    int       `json:"score"`
	Grade    string    `json:"grade"`
	Findings []Finding `json:"findings"`
}

type Summary struct {
	TotalServices int `json:"total_services"`
	WithPidHost   int `json:"with_pid_host"`
	WithPidCustom int `json:"with_pid_custom"`
	WithDefault   int `json:"with_default"`
	TotalFindings int `json:"total_findings"`
	OverallScore  int `json:"overall_score"`
	OverallGrade  string `json:"overall_grade"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func Analyze(c collect.Collected) Report {
	var results []ServiceResult
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			r := analyzeService(svc, cf.Path)
			results = append(results, r)
		}
	}

	summary := buildSummary(results)
	return Report{Services: results, Summary: summary}
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	r := ServiceResult{
		Name:    svc.Name,
		PidMode: svc.PidMode,
		Score:   100,
	}

	pid := strings.ToLower(svc.PidMode)

	if pid == "host" {
		r.Findings = append(r.Findings, Finding{
			Service:  svc.Name,
			File:     file,
			Severity: "high",
			Category: "pid_host_mode",
			Detail:   "pid: host shares the host PID namespace; container can see and signal all host processes",
		})
		r.Score -= 40
	}

	if pid == "host" && svc.Privileged {
		r.Findings = append(r.Findings, Finding{
			Service:  svc.Name,
			File:     file,
			Severity: "critical",
			Category: "privileged_pid_host",
			Detail:   "privileged container with pid: host can control any host process",
		})
		r.Score -= 30
	}

	if pid != "" && pid != "host" {
		pidParts := strings.SplitN(pid, ":", 2)
		if len(pidParts) == 2 && pidParts[0] == "container" {
			r.Findings = append(r.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "medium",
				Category: "pid_shared_container",
				Detail:   fmt.Sprintf("pid namespace shared with container %q; processes visible across containers", pidParts[1]),
			})
			r.Score -= 15
		}
	}

	if r.Score < 0 {
		r.Score = 0
	}
	r.Grade = scoreToGrade(r.Score)
	return r
}

func buildSummary(results []ServiceResult) Summary {
	s := Summary{TotalServices: len(results)}
	totalScore := 0
	for _, r := range results {
		totalScore += r.Score
		s.TotalFindings += len(r.Findings)
		pid := strings.ToLower(r.PidMode)
		switch {
		case pid == "host":
			s.WithPidHost++
		case pid != "":
			s.WithPidCustom++
		default:
			s.WithDefault++
		}
	}
	if len(results) > 0 {
		s.OverallScore = totalScore / len(results)
	} else {
		s.OverallScore = 100
	}
	s.OverallGrade = scoreToGrade(s.OverallScore)
	return s
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
	b.WriteString("PID Namespace Audit\n")
	b.WriteString(strings.Repeat("=", 40) + "\n")
	fmt.Fprintf(&b, "Services scanned:    %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "With pid: host:      %d\n", r.Summary.WithPidHost)
	fmt.Fprintf(&b, "With pid: custom:    %d\n", r.Summary.WithPidCustom)
	fmt.Fprintf(&b, "With default PID ns: %d\n", r.Summary.WithDefault)
	fmt.Fprintf(&b, "Overall score:       %d/100 (%s)\n\n", r.Summary.OverallScore, r.Summary.OverallGrade)

	for _, svc := range r.Services {
		if len(svc.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (pid: %s, score: %d %s)\n", svc.Name, svc.PidMode, svc.Score, svc.Grade)
		for _, f := range svc.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.Category, f.Detail)
		}
	}
	return b.String()
}
