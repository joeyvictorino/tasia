package signalforward

import (
	"fmt"
	"regexp"
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
	ShellEntrypoint int `json:"shell_entrypoint"`
	NoStopSignal    int `json:"no_stop_signal"`
	ShortGrace      int `json:"short_grace"`
	TtyWithoutInit  int `json:"tty_without_init"`
	NoTrapHandler   int `json:"no_trap_handler"`
}

var shellEntryRegex = regexp.MustCompile(`(?i)(/bin/)?(ba)?sh\s+-c`)
var trapRegex = regexp.MustCompile(`(?i)\btrap\b`)

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

	checkInit(&sr, svc)
	checkShellEntrypoint(&sr, svc)
	checkStopSignal(&sr, svc)
	checkGracePeriod(&sr, svc)
	checkTtyWithoutInit(&sr, svc)
	checkTrapHandler(&sr, svc)

	return sr
}

func checkInit(sr *ServiceResult, svc compose.Service) {
	if !svc.Init && !svc.Tty {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "signal_no_init",
			Message: fmt.Sprintf("Service '%s' runs without init: true; PID 1 process may not forward signals to child processes, causing orphaned zombies on shutdown", svc.Name),
		})
	}
}

func checkShellEntrypoint(sr *ServiceResult, svc compose.Service) {
	ep := strings.Join(svc.Entrypoint, " ")
	cmd := strings.Join(svc.Command, " ")
	combined := ep + " " + cmd

	if shellEntryRegex.MatchString(combined) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "signal_shell_entrypoint",
			Message: fmt.Sprintf("Service '%s' uses shell-form entrypoint (sh -c); shell does not forward signals to child process by default, causing unclean shutdown", svc.Name),
		})
	}
}

func checkStopSignal(sr *ServiceResult, svc compose.Service) {
	if svc.StopSignal == "" {
		return
	}
	upper := strings.ToUpper(svc.StopSignal)
	if upper == "SIGKILL" || upper == "9" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "signal_no_stop_signal",
			Message: fmt.Sprintf("Service '%s' uses SIGKILL as stop signal; process has no chance to perform graceful shutdown or flush data", svc.Name),
		})
	}
}

func checkGracePeriod(sr *ServiceResult, svc compose.Service) {
	if svc.StopGracePeriod == "" {
		return
	}
	grace := strings.TrimSpace(svc.StopGracePeriod)
	if grace == "0" || grace == "0s" || grace == "0m" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "signal_short_grace",
			Message: fmt.Sprintf("Service '%s' has zero stop grace period; container is killed immediately without time for graceful shutdown", svc.Name),
		})
	}
	if grace == "1s" || grace == "2s" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "signal_short_grace",
			Message: fmt.Sprintf("Service '%s' has very short stop grace period (%s); AI model inference may need more time to complete in-flight requests", svc.Name, grace),
		})
	}
}

func checkTtyWithoutInit(sr *ServiceResult, svc compose.Service) {
	if svc.Tty && !svc.Init {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "signal_tty_without_init",
			Message: fmt.Sprintf("Service '%s' allocates a TTY without init process; TTY signal handling may not propagate correctly to child processes", svc.Name),
		})
	}
}

func checkTrapHandler(sr *ServiceResult, svc compose.Service) {
	ep := strings.Join(svc.Entrypoint, " ")
	cmd := strings.Join(svc.Command, " ")
	combined := ep + " " + cmd

	if shellEntryRegex.MatchString(combined) && !trapRegex.MatchString(combined) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "signal_no_trap_handler",
			Message: fmt.Sprintf("Service '%s' uses shell entrypoint without trap handler; signals will be silently dropped instead of forwarded to child processes", svc.Name),
		})
	}
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "signal_no_init":
				s.NoInit++
			case "signal_shell_entrypoint":
				s.ShellEntrypoint++
			case "signal_no_stop_signal":
				s.NoStopSignal++
			case "signal_short_grace":
				s.ShortGrace++
			case "signal_tty_without_init":
				s.TtyWithoutInit++
			case "signal_no_trap_handler":
				s.NoTrapHandler++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Signal Forwarding Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No init process:          %d\n", r.Summary.NoInit)
	fmt.Fprintf(&b, "  Shell-form entrypoint:    %d\n", r.Summary.ShellEntrypoint)
	fmt.Fprintf(&b, "  SIGKILL stop signal:      %d\n", r.Summary.NoStopSignal)
	fmt.Fprintf(&b, "  Short grace period:       %d\n", r.Summary.ShortGrace)
	fmt.Fprintf(&b, "  TTY without init:         %d\n", r.Summary.TtyWithoutInit)
	fmt.Fprintf(&b, "  No trap handler:          %d\n\n", r.Summary.NoTrapHandler)
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
