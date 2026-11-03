package initproc

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
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices       int `json:"total_services"`
	TotalFindings       int `json:"total_findings"`
	MissingInit         int `json:"missing_init"`
	InitWithPid1        int `json:"init_with_pid1"`
	InitPrivileged      int `json:"init_privileged"`
	InitOomDisabled     int `json:"init_oom_disabled"`
	InitStopSignal      int `json:"init_stop_signal"`
	InitNoGracePeriod   int `json:"init_no_grace_period"`
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

	if !svc.Init && svc.PidMode != "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "missing_init",
			Message: fmt.Sprintf("Service '%s' has no init process (init: true); may accumulate zombie processes and mishandle signals", svc.Name),
		})
	}

	if svc.PidMode == "host" && !svc.Init {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "pid_host_no_init",
			Message: fmt.Sprintf("Service '%s' uses pid:host without init; host PID namespace inherits host's init but container process still may not reap children", svc.Name),
		})
	}

	if svc.Init && svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "init_privileged",
			Message: fmt.Sprintf("Service '%s' runs init in privileged mode; init process has full host access", svc.Name),
		})
	}

	if svc.Init && svc.OomKillDisable {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "init_oom_disabled",
			Message: fmt.Sprintf("Service '%s' has init with OOM kill disabled; if init is OOM-protected, zombie cleanup never stops but container may exhaust memory", svc.Name),
		})
	}

	if !svc.Init && svc.StopSignal != "" && svc.StopSignal != "SIGTERM" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "custom_stop_no_init",
			Message: fmt.Sprintf("Service '%s' uses custom stop_signal '%s' without init; signal may not reach the application process correctly", svc.Name, svc.StopSignal),
		})
	}

	if !svc.Init && svc.StopGracePeriod == "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "no_init_no_grace",
			Message: fmt.Sprintf("Service '%s' has no init and no stop_grace_period; may be killed abruptly with SIGKILL after default timeout", svc.Name),
		})
	}

	if svc.Init && hasLongRunningEntrypoint(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "init_shell_entrypoint",
			Message: fmt.Sprintf("Service '%s' uses init with shell-form entrypoint; init wraps /bin/sh which wraps the actual process (double fork)", svc.Name),
		})
	}

	return sr
}

func hasLongRunningEntrypoint(svc compose.Service) bool {
	if len(svc.Entrypoint) == 1 {
		ep := svc.Entrypoint[0]
		return strings.Contains(ep, "&&") || strings.Contains(ep, ";") || strings.Contains(ep, "|")
	}
	if len(svc.Command) == 1 {
		cmd := svc.Command[0]
		return strings.Contains(cmd, "&&") || strings.Contains(cmd, ";") || strings.Contains(cmd, "|")
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "missing_init":
				s.MissingInit++
			case "pid_host_no_init":
				s.InitWithPid1++
			case "init_privileged":
				s.InitPrivileged++
			case "init_oom_disabled":
				s.InitOomDisabled++
			case "custom_stop_no_init":
				s.InitStopSignal++
			case "no_init_no_grace":
				s.InitNoGracePeriod++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Init Process Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Missing init:          %d\n", r.Summary.MissingInit)
	fmt.Fprintf(&b, "  PID host no init:      %d\n", r.Summary.InitWithPid1)
	fmt.Fprintf(&b, "  Init privileged:       %d\n", r.Summary.InitPrivileged)
	fmt.Fprintf(&b, "  Init OOM disabled:     %d\n", r.Summary.InitOomDisabled)
	fmt.Fprintf(&b, "  Custom stop no init:   %d\n", r.Summary.InitStopSignal)
	fmt.Fprintf(&b, "  No init no grace:      %d\n\n", r.Summary.InitNoGracePeriod)
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
