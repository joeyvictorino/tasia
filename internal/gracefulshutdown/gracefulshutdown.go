package gracefulshutdown

import (
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
	TotalServices   int `json:"total_services"`
	TotalFindings   int `json:"total_findings"`
	NoInit          int `json:"no_init"`
	BadStopSignal   int `json:"bad_stop_signal"`
	GraceTooShort   int `json:"grace_too_short"`
	GraceTooLong    int `json:"grace_too_long"`
	MissingGrace    int `json:"missing_grace"`
	PrivilegedNoInit int `json:"privileged_no_init"`
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

	if !svc.Init {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "shutdown_no_init",
			Message: fmt.Sprintf("Service '%s' has no init process (init: true); zombie processes may accumulate on shutdown", svc.Name),
		})
	}

	if svc.StopSignal != "" {
		sig := strings.ToUpper(svc.StopSignal)
		dangerousSignals := map[string]bool{
			"SIGKILL": true, "KILL": true, "9": true,
			"SIGSTOP": true, "STOP": true, "19": true,
		}
		if dangerousSignals[sig] {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "shutdown_bad_stop_signal",
				Message: fmt.Sprintf("Service '%s' uses stop_signal '%s'; prevents graceful shutdown cleanup", svc.Name, svc.StopSignal),
			})
		}
	}

	if svc.StopGracePeriod != "" {
		seconds := parseDuration(svc.StopGracePeriod)
		if seconds > 0 && seconds < 5 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "shutdown_grace_too_short",
				Message: fmt.Sprintf("Service '%s' has stop_grace_period '%s' (< 5s); may not allow enough time for graceful shutdown", svc.Name, svc.StopGracePeriod),
			})
		}
		if seconds > 300 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "shutdown_grace_too_long",
				Message: fmt.Sprintf("Service '%s' has stop_grace_period '%s' (> 5m); delayed shutdown may block orchestrator operations", svc.Name, svc.StopGracePeriod),
			})
		}
	} else {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "shutdown_missing_grace",
			Message: fmt.Sprintf("Service '%s' has no explicit stop_grace_period; relies on Docker default (10s)", svc.Name),
		})
	}

	if svc.Privileged && !svc.Init {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "shutdown_privileged_no_init",
			Message: fmt.Sprintf("Service '%s' is privileged without init; orphan processes from privileged container may persist on host", svc.Name),
		})
	}

	return sr
}

func parseDuration(s string) int {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0
	}

	switch {
	case strings.HasSuffix(s, "ms"):
		s = strings.TrimSuffix(s, "ms")
		n, _ := strconv.Atoi(s)
		return n / 1000
	case strings.HasSuffix(s, "s"):
		s = strings.TrimSuffix(s, "s")
		n, _ := strconv.Atoi(s)
		return n
	case strings.HasSuffix(s, "m"):
		s = strings.TrimSuffix(s, "m")
		n, _ := strconv.Atoi(s)
		return n * 60
	case strings.HasSuffix(s, "h"):
		s = strings.TrimSuffix(s, "h")
		n, _ := strconv.Atoi(s)
		return n * 3600
	default:
		n, _ := strconv.Atoi(s)
		return n
	}
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "shutdown_no_init":
				s.NoInit++
			case "shutdown_bad_stop_signal":
				s.BadStopSignal++
			case "shutdown_grace_too_short":
				s.GraceTooShort++
			case "shutdown_grace_too_long":
				s.GraceTooLong++
			case "shutdown_missing_grace":
				s.MissingGrace++
			case "shutdown_privileged_no_init":
				s.PrivilegedNoInit++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Graceful Shutdown Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No init process:        %d\n", r.Summary.NoInit)
	fmt.Fprintf(&b, "  Bad stop signal:        %d\n", r.Summary.BadStopSignal)
	fmt.Fprintf(&b, "  Grace period too short: %d\n", r.Summary.GraceTooShort)
	fmt.Fprintf(&b, "  Grace period too long:  %d\n", r.Summary.GraceTooLong)
	fmt.Fprintf(&b, "  Missing grace period:   %d\n", r.Summary.MissingGrace)
	fmt.Fprintf(&b, "  Privileged + no init:   %d\n\n", r.Summary.PrivilegedNoInit)
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
