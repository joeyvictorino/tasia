package runtimeaudit

import (
	"fmt"
	"strconv"
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
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Name     string    `json:"name"`
	File     string    `json:"file"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices   int `json:"total_services"`
	TotalFindings   int `json:"total_findings"`
	NoReadOnly      int `json:"no_read_only"`
	InteractiveMode int `json:"interactive_mode"`
	NoInit          int `json:"no_init"`
	StopGraceIssues int `json:"stop_grace_issues"`
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
		summary.TotalFindings += len(s.Findings)
		for _, f := range s.Findings {
			switch f.RuleID {
			case "runtime_no_readonly":
				summary.NoReadOnly++
			case "runtime_interactive":
				summary.InteractiveMode++
			case "runtime_no_init":
				summary.NoInit++
			case "runtime_stop_grace":
				summary.StopGraceIssues++
			}
		}
	}
	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{Name: svc.Name, File: file}

	if !svc.ReadOnly {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "runtime_no_readonly",
			Severity:    "medium",
			Detail:      "Root filesystem is writable; a compromised process can modify container binaries or plant persistence",
			Remediation: "Add read_only: true and use tmpfs or named volumes for writable paths",
		})
	}

	if svc.StdinOpen && svc.Tty {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "runtime_interactive",
			Severity:    "medium",
			Detail:      "stdin_open and tty are both enabled; interactive mode in production enables shell escape and attach-based attacks",
			Remediation: "Remove stdin_open and tty unless this service requires interactive debugging",
		})
	}

	if !svc.Init {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "runtime_no_init",
			Severity:    "low",
			Detail:      "No init process configured; PID 1 will not reap zombie child processes, causing resource leaks",
			Remediation: "Add init: true to enable tini as PID 1 for proper signal forwarding and zombie reaping",
		})
	}

	if svc.StopGracePeriod != "" {
		secs := parseGracePeriod(svc.StopGracePeriod)
		if secs > 30 {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				File:        file,
				RuleID:      "runtime_stop_grace",
				Severity:    "low",
				Detail:      fmt.Sprintf("stop_grace_period is %s (%ds); long grace periods allow compromised processes to persist during shutdown", svc.StopGracePeriod, secs),
				Remediation: "Set stop_grace_period to 30s or less unless the service requires extended shutdown for data integrity",
			})
		}
	}

	if strings.ToLower(svc.Runtime) == "nvidia" && !svc.ReadOnly {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			File:        file,
			RuleID:      "runtime_nvidia_no_hardening",
			Severity:    "medium",
			Detail:      "NVIDIA runtime with writable root filesystem; GPU workloads should have filesystem hardening",
			Remediation: "Add read_only: true when using runtime: nvidia to limit GPU container attack surface",
		})
	}

	return sr
}

func parseGracePeriod(s string) int {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasSuffix(s, "m") {
		if n, err := strconv.Atoi(strings.TrimSuffix(s, "m")); err == nil {
			return n * 60
		}
	}
	if strings.HasSuffix(s, "s") {
		if n, err := strconv.Atoi(strings.TrimSuffix(s, "s")); err == nil {
			return n
		}
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return 0
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Container Runtime Audit (%d services, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No read_only:       %d\n", r.Summary.NoReadOnly)
	fmt.Fprintf(&b, "  Interactive mode:   %d\n", r.Summary.InteractiveMode)
	fmt.Fprintf(&b, "  No init process:    %d\n", r.Summary.NoInit)
	fmt.Fprintf(&b, "  Stop grace issues:  %d\n\n", r.Summary.StopGraceIssues)

	for _, s := range r.Services {
		if len(s.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%s)\n", s.Name, s.File)
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.RuleID, f.Detail)
			fmt.Fprintf(&b, "           Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
	return b.String()
}
