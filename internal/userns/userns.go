package userns

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
	Name       string    `json:"name"`
	File       string    `json:"file"`
	UsernsMode string    `json:"userns_mode,omitempty"`
	Privileged bool      `json:"privileged"`
	Findings   []Finding `json:"findings,omitempty"`
	Score      int       `json:"score"`
	Grade      string    `json:"grade"`
}

type Summary struct {
	TotalServices       int `json:"total_services"`
	WithUsernsHost      int `json:"with_userns_host"`
	WithPrivileged      int `json:"with_privileged"`
	WithNoUsernsAndPriv int `json:"with_no_userns_and_priv"`
	WithIssues          int `json:"with_issues"`
	TotalFindings       int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func Analyze(collected collect.Collected) Report {
	var services []ServiceResult

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf)
			services = append(services, sr)
		}
	}

	summary := buildSummary(services)

	return Report{
		Services: services,
		Summary:  summary,
	}
}

func analyzeService(svc compose.Service, cf compose.File) ServiceResult {
	sr := ServiceResult{
		Name:       svc.Name,
		File:       cf.Path,
		UsernsMode: svc.UsernsMode,
		Privileged: svc.Privileged,
		Score:      100,
	}

	mode := strings.ToLower(svc.UsernsMode)

	if mode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "high",
			Category: "userns_host_mode",
			Detail:   fmt.Sprintf("Service '%s' uses userns_mode: host, sharing the host's user namespace and bypassing UID isolation", svc.Name),
		})
		sr.Score -= 40
	}

	if svc.Privileged && mode != "host" && mode == "" {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "medium",
			Category: "privileged_no_userns",
			Detail:   fmt.Sprintf("Service '%s' is privileged without explicit user namespace remapping; consider userns_mode to limit host UID access", svc.Name),
		})
		sr.Score -= 20
	}

	if svc.Privileged && mode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "critical",
			Category: "privileged_userns_host",
			Detail:   fmt.Sprintf("Service '%s' is privileged with userns_mode: host, combining full capabilities with no UID isolation", svc.Name),
		})
		sr.Score -= 30
	}

	hasRootImage := false
	imgLower := strings.ToLower(svc.Image)
	for _, env := range svc.Environment {
		if strings.HasPrefix(env, "USER=root") {
			hasRootImage = true
		}
	}
	for _, lbl := range svc.Labels {
		if strings.Contains(strings.ToLower(lbl), "run-as-root") {
			hasRootImage = true
		}
	}
	if strings.Contains(imgLower, "root") {
		hasRootImage = true
	}

	if hasRootImage && mode == "" {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     cf.Path,
			Severity: "low",
			Category: "root_without_userns",
			Detail:   fmt.Sprintf("Service '%s' appears to run as root without user namespace remapping", svc.Name),
		})
		sr.Score -= 10
	}

	if sr.Score < 0 {
		sr.Score = 0
	}
	sr.Grade = scoreToGrade(sr.Score)
	return sr
}

func buildSummary(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		if strings.ToLower(sr.UsernsMode) == "host" {
			s.WithUsernsHost++
		}
		if sr.Privileged {
			s.WithPrivileged++
		}
		if sr.Privileged && sr.UsernsMode == "" {
			s.WithNoUsernsAndPriv++
		}
		if len(sr.Findings) > 0 {
			s.WithIssues++
		}
		s.TotalFindings += len(sr.Findings)
	}
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
	b.WriteString("User Namespace Audit\n")
	b.WriteString(strings.Repeat("=", 40) + "\n")
	fmt.Fprintf(&b, "Services scanned:      %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "Using userns_mode host: %d\n", r.Summary.WithUsernsHost)
	fmt.Fprintf(&b, "Privileged:            %d\n", r.Summary.WithPrivileged)
	fmt.Fprintf(&b, "Total findings:        %d\n\n", r.Summary.TotalFindings)

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%s) [%s]\n", sr.Name, sr.File, sr.Grade)
		if sr.UsernsMode != "" {
			fmt.Fprintf(&b, "    userns_mode: %s\n", sr.UsernsMode)
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.Category, f.Detail)
		}
		b.WriteString("\n")
	}
	return b.String()
}
