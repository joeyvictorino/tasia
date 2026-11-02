package ipcns

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
	IpcMode  string    `json:"ipc_mode"`
	Score    int       `json:"score"`
	Grade    string    `json:"grade"`
	Findings []Finding `json:"findings"`
}

type Summary struct {
	TotalServices int `json:"total_services"`
	WithIpcHost   int `json:"with_ipc_host"`
	WithIpcShared int `json:"with_ipc_shared"`
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
		IpcMode: svc.IpcMode,
		Score:   100,
	}

	ipc := strings.ToLower(svc.IpcMode)

	if ipc == "host" {
		r.Findings = append(r.Findings, Finding{
			Service:  svc.Name,
			File:     file,
			Severity: "high",
			Category: "ipc_host_mode",
			Detail:   "ipc: host shares the host IPC namespace; container can access host shared memory segments",
		})
		r.Score -= 35
	}

	if ipc == "host" && svc.Privileged {
		r.Findings = append(r.Findings, Finding{
			Service:  svc.Name,
			File:     file,
			Severity: "critical",
			Category: "privileged_ipc_host",
			Detail:   "privileged container with ipc: host can manipulate host shared memory and semaphores",
		})
		r.Score -= 30
	}

	if ipc != "" && ipc != "host" {
		ipcParts := strings.SplitN(ipc, ":", 2)
		if len(ipcParts) == 2 && ipcParts[0] == "container" {
			r.Findings = append(r.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "medium",
				Category: "ipc_shared_container",
				Detail:   fmt.Sprintf("IPC namespace shared with container %q; shared memory accessible across containers", ipcParts[1]),
			})
			r.Score -= 15
		}
	}

	if ipc == "host" && hasSharedMemoryVolume(svc) {
		r.Findings = append(r.Findings, Finding{
			Service:  svc.Name,
			File:     file,
			Severity: "high",
			Category: "ipc_host_with_shm",
			Detail:   "ipc: host combined with /dev/shm mount increases shared memory attack surface",
		})
		r.Score -= 10
	}

	if r.Score < 0 {
		r.Score = 0
	}
	r.Grade = scoreToGrade(r.Score)
	return r
}

func hasSharedMemoryVolume(svc compose.Service) bool {
	for _, v := range svc.Volumes {
		if strings.Contains(v, "/dev/shm") {
			return true
		}
	}
	return false
}

func buildSummary(results []ServiceResult) Summary {
	s := Summary{TotalServices: len(results)}
	totalScore := 0
	for _, r := range results {
		totalScore += r.Score
		s.TotalFindings += len(r.Findings)
		ipc := strings.ToLower(r.IpcMode)
		switch {
		case ipc == "host":
			s.WithIpcHost++
		case ipc != "":
			s.WithIpcShared++
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
	b.WriteString("IPC Namespace Audit\n")
	b.WriteString(strings.Repeat("=", 40) + "\n")
	fmt.Fprintf(&b, "Services scanned:    %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "With ipc: host:      %d\n", r.Summary.WithIpcHost)
	fmt.Fprintf(&b, "With ipc: shared:    %d\n", r.Summary.WithIpcShared)
	fmt.Fprintf(&b, "With default IPC ns: %d\n", r.Summary.WithDefault)
	fmt.Fprintf(&b, "Overall score:       %d/100 (%s)\n\n", r.Summary.OverallScore, r.Summary.OverallGrade)

	for _, svc := range r.Services {
		if len(svc.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (ipc: %s, score: %d %s)\n", svc.Name, svc.IpcMode, svc.Score, svc.Grade)
		for _, f := range svc.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.Category, f.Detail)
		}
	}
	return b.String()
}
