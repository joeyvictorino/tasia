package healthprobe

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type ProbeFinding struct {
	Service  string `json:"service"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type ServiceProbe struct {
	Name        string `json:"name"`
	HasHealth   bool   `json:"has_healthcheck"`
	Test        string `json:"test,omitempty"`
	Interval    string `json:"interval,omitempty"`
	Timeout     string `json:"timeout,omitempty"`
	Retries     int    `json:"retries,omitempty"`
	StartPeriod string `json:"start_period,omitempty"`
}

type Summary struct {
	TotalServices      int    `json:"total_services"`
	WithHealthcheck    int    `json:"with_healthcheck"`
	WithoutHealthcheck int    `json:"without_healthcheck"`
	Findings           int    `json:"findings"`
	HighSev            int    `json:"high_severity"`
	MediumSev          int    `json:"medium_severity"`
	LowSev             int    `json:"low_severity"`
	Score              int    `json:"score"`
	Grade              string `json:"grade"`
}

type Report struct {
	Probes   []ServiceProbe `json:"probes"`
	Findings []ProbeFinding `json:"findings"`
	Summary  Summary        `json:"summary"`
}

func Analyze(collected *collect.Collected) Report {
	var probes []ServiceProbe
	var findings []ProbeFinding

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			sp := ServiceProbe{Name: svc.Name}

			if svc.Healthcheck == nil || (len(svc.Healthcheck.Test) == 0 && !svc.Healthcheck.Disable) {
				sp.HasHealth = false
				findings = append(findings, ProbeFinding{
					Service:  svc.Name,
					Category: "no-healthcheck",
					Severity: "medium",
					Message:  "Service has no healthcheck configured",
				})
			} else if svc.Healthcheck.Disable {
				sp.HasHealth = false
				findings = append(findings, ProbeFinding{
					Service:  svc.Name,
					Category: "healthcheck-disabled",
					Severity: "medium",
					Message:  "Healthcheck is explicitly disabled",
				})
			} else {
				hc := svc.Healthcheck
				sp.HasHealth = true
				sp.Test = strings.Join(hc.Test, " ")
				sp.Interval = hc.Interval
				sp.Timeout = hc.Timeout
				sp.Retries = hc.Retries
				sp.StartPeriod = hc.StartPeriod

				if hc.Interval == "" {
					findings = append(findings, ProbeFinding{
						Service:  svc.Name,
						Category: "missing-interval",
						Severity: "low",
						Message:  "Healthcheck has no interval configured (uses Docker default 30s)",
					})
				}

				if hc.Timeout == "" {
					findings = append(findings, ProbeFinding{
						Service:  svc.Name,
						Category: "missing-timeout",
						Severity: "low",
						Message:  "Healthcheck has no timeout configured (uses Docker default 30s)",
					})
				}

				if hc.Retries == 0 {
					findings = append(findings, ProbeFinding{
						Service:  svc.Name,
						Category: "missing-retries",
						Severity: "low",
						Message:  "Healthcheck has no retries configured (uses Docker default 3)",
					})
				}

				if hc.StartPeriod == "" {
					findings = append(findings, ProbeFinding{
						Service:  svc.Name,
						Category: "missing-start-period",
						Severity: "low",
						Message:  "Healthcheck has no start_period, may fail during slow startup",
					})
				}

				testStr := sp.Test
				if strings.Contains(testStr, "curl") && !strings.Contains(testStr, "--fail") {
					findings = append(findings, ProbeFinding{
						Service:  svc.Name,
						Category: "curl-no-fail",
						Severity: "medium",
						Message:  "Healthcheck uses curl without --fail flag; HTTP errors won't be detected",
					})
				}
			}

			probes = append(probes, sp)
		}
	}

	sort.Slice(probes, func(i, j int) bool {
		return probes[i].Name < probes[j].Name
	})

	sort.Slice(findings, func(i, j int) bool {
		si, sj := sevOrd(findings[i].Severity), sevOrd(findings[j].Severity)
		if si != sj {
			return si < sj
		}
		return findings[i].Service < findings[j].Service
	})

	high, med, low := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case "high":
			high++
		case "medium":
			med++
		case "low":
			low++
		}
	}

	withHC := 0
	for _, p := range probes {
		if p.HasHealth {
			withHC++
		}
	}

	score := 100 - high*15 - med*5 - low*2
	if score < 0 {
		score = 0
	}

	return Report{
		Probes:   probes,
		Findings: findings,
		Summary: Summary{
			TotalServices:      len(probes),
			WithHealthcheck:    withHC,
			WithoutHealthcheck: len(probes) - withHC,
			Findings:           len(findings),
			HighSev:            high,
			MediumSev:          med,
			LowSev:             low,
			Score:              score,
			Grade:              scoreGrade(score),
		},
	}
}

func sevOrd(s string) int {
	switch s {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}

func scoreGrade(score int) string {
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
	var sb strings.Builder
	sb.WriteString("Health Probe Analysis\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&sb, "  Services:           %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&sb, "  With healthcheck:   %d\n", r.Summary.WithHealthcheck)
	fmt.Fprintf(&sb, "  Without:            %d\n", r.Summary.WithoutHealthcheck)
	fmt.Fprintf(&sb, "  Findings:           %d\n", r.Summary.Findings)
	fmt.Fprintf(&sb, "  Score:              %d/100 (%s)\n\n", r.Summary.Score, r.Summary.Grade)

	if len(r.Probes) > 0 {
		sb.WriteString("Probes:\n")
		for _, p := range r.Probes {
			status := "none"
			if p.HasHealth {
				status = p.Test
			}
			fmt.Fprintf(&sb, "  %s: %s\n", p.Name, status)
		}
		sb.WriteString("\n")
	}

	if len(r.Findings) > 0 {
		sb.WriteString("Findings:\n")
		for i, f := range r.Findings {
			fmt.Fprintf(&sb, "  %d. [%s] %s: %s (%s)\n",
				i+1, strings.ToUpper(f.Severity), f.Service, f.Message, f.Category)
		}
	}

	return sb.String()
}
