package oom

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service     string `json:"service"`
	File        string `json:"file"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Value       string `json:"value,omitempty"`
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Name     string    `json:"name"`
	File     string    `json:"file"`
	MemLimit string    `json:"mem_limit,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	ServicesNoLimit   int `json:"services_no_limit"`
	OomKillDisabled  int `json:"oom_kill_disabled"`
	LowOomScore      int `json:"low_oom_score"`
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
		for _, f := range s.Findings {
			summary.TotalFindings++
			switch f.RuleID {
			case "oom_no_limit":
				summary.ServicesNoLimit++
			case "oom_kill_disabled":
				summary.OomKillDisabled++
			case "oom_score_low":
				summary.LowOomScore++
			}
		}
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:     svc.Name,
		File:     file,
		MemLimit: svc.MemLimit,
	}

	if svc.MemLimit == "" {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "oom_no_limit",
			Severity:    "medium",
			Detail:      "No memory limit configured; container can consume all host memory and trigger OOM kills on other services",
			Remediation: "Set mem_limit (e.g. mem_limit: 512m) or deploy.resources.limits.memory to bound memory usage",
		})
	}

	if svc.OomKillDisable {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "oom_kill_disabled",
			Severity:    "high",
			Detail:      "OOM killer disabled; if this container exhausts memory, the host kernel cannot reclaim it and may hang",
			Value:       "true",
			Remediation: "Remove oom_kill_disable: true; let the OOM killer terminate runaway processes instead of risking host stability",
		})
	}

	if svc.OomScoreAdjSet && svc.OomScoreAdj < -500 {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "oom_score_low",
			Severity:    "medium",
			Detail:      fmt.Sprintf("OOM score adjustment set to %d; very negative values make this container unlikely to be killed, shifting OOM risk to other services", svc.OomScoreAdj),
			Value:       fmt.Sprintf("%d", svc.OomScoreAdj),
			Remediation: "Avoid setting oom_score_adj below -500 unless this service is truly critical; prefer proper memory limits instead",
		})
	}

	if svc.MemLimit != "" && svc.MemswapLimit == "" {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "oom_no_swap_limit",
			Severity:    "low",
			Detail:      "Memory limit set but no swap limit (memswap_limit); container may use unlimited swap, degrading host performance",
			Value:       svc.MemLimit,
			Remediation: "Set memswap_limit equal to mem_limit to disable swap, or to a reasonable multiple (e.g. 2x mem_limit)",
		})
	}

	return sr
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "OOM Kill Risk Analysis (%d services, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.TotalFindings)

	fmt.Fprintf(&b, "  Services without memory limit: %d\n", r.Summary.ServicesNoLimit)
	fmt.Fprintf(&b, "  OOM killer disabled:           %d\n", r.Summary.OomKillDisabled)
	fmt.Fprintf(&b, "  Low OOM score adjustment:      %d\n\n", r.Summary.LowOomScore)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%s)\n", s.Name, s.File)
		if s.MemLimit != "" {
			fmt.Fprintf(&b, "    mem_limit: %s\n", s.MemLimit)
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.RuleID, f.Detail)
			fmt.Fprintf(&b, "           Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
	return b.String()
}
