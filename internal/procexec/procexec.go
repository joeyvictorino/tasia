package procexec

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
	TotalServices     int `json:"total_services"`
	TotalFindings     int `json:"total_findings"`
	ShellAccess       int `json:"shell_access"`
	UnrestrictedExec  int `json:"unrestricted_exec"`
	DangerousCommands int `json:"dangerous_commands"`
	DebugShells       int `json:"debug_shells"`
}

var dangerousShells = []string{
	"/bin/sh", "/bin/bash", "/bin/zsh", "/bin/ash",
	"/usr/bin/sh", "/usr/bin/bash", "/usr/bin/zsh",
	"sh", "bash", "zsh", "ash",
}

var dangerousCommands = []string{
	"curl", "wget", "nc", "ncat", "netcat",
	"python", "python3", "ruby", "perl", "php",
	"gcc", "g++", "make", "cmake",
	"apt-get", "apk", "yum", "dnf", "pip", "npm",
}

var debugEntrypoints = []string{
	"sleep infinity", "tail -f /dev/null", "sleep 999",
	"cat /dev/null", "/bin/sh -c while true", "sleep 86400",
}

func isShell(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	for _, s := range dangerousShells {
		if cmd == s {
			return true
		}
	}
	return false
}

func isDangerousCommand(cmd string) bool {
	lower := strings.ToLower(cmd)
	for _, d := range dangerousCommands {
		if lower == d || strings.HasPrefix(lower, d+" ") {
			return true
		}
	}
	return false
}

func isDebugEntrypoint(entrypoint string) bool {
	lower := strings.ToLower(strings.TrimSpace(entrypoint))
	for _, d := range debugEntrypoints {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
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

func joinCmd(parts []string) string {
	return strings.Join(parts, " ")
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if len(svc.Entrypoint) > 0 {
		if isShell(svc.Entrypoint[0]) {
			if len(svc.Entrypoint) == 1 || (len(svc.Entrypoint) == 2 && svc.Entrypoint[1] == "-c" && len(svc.Command) == 0) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "shell_entrypoint",
					Message: fmt.Sprintf("Service '%s' uses bare shell '%s' as entrypoint; provides interactive shell access to the container", svc.Name, joinCmd(svc.Entrypoint)),
				})
			}
		}
		epStr := joinCmd(svc.Entrypoint)
		if isDebugEntrypoint(epStr) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "debug_entrypoint",
				Message: fmt.Sprintf("Service '%s' uses debug/sleep entrypoint '%s'; container stays running with no real workload, typically used for shell access", svc.Name, epStr),
			})
		}
	}

	if len(svc.Command) > 0 {
		if isShell(svc.Command[0]) && len(svc.Command) == 1 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "shell_command",
				Message: fmt.Sprintf("Service '%s' runs bare shell '%s' as command; provides interactive shell access", svc.Name, joinCmd(svc.Command)),
			})
		}
		cmdStr := joinCmd(svc.Command)
		if isDebugEntrypoint(cmdStr) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "debug_command",
				Message: fmt.Sprintf("Service '%s' uses debug/sleep command '%s'; container stays running idle", svc.Name, cmdStr),
			})
		}

		for _, p := range svc.Command {
			base := extractBasename(p)
			if isDangerousCommand(base) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "dangerous_command",
					Message: fmt.Sprintf("Service '%s' command invokes '%s'; network tools, compilers, and package managers should not be available in production containers", svc.Name, base),
				})
				break
			}
		}
	}

	for _, cap := range svc.CapAdd {
		upper := strings.ToUpper(strings.TrimSpace(cap))
		if upper == "SYS_PTRACE" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "ptrace_capability",
				Message: fmt.Sprintf("Service '%s' adds SYS_PTRACE capability; enables process inspection, debugging, and code injection into other processes", svc.Name),
			})
		}
		if upper == "SYS_ADMIN" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "sysadmin_capability",
				Message: fmt.Sprintf("Service '%s' adds SYS_ADMIN capability; grants broad system administration powers including mount, namespace, and BPF operations", svc.Name),
			})
		}
	}

	if svc.StdinOpen && svc.Tty {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "interactive_mode",
			Message: fmt.Sprintf("Service '%s' has both stdin_open and tty enabled; container is configured for interactive terminal access", svc.Name),
		})
	}

	return sr
}

func extractBasename(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "shell_entrypoint", "shell_command":
				s.ShellAccess++
			case "ptrace_capability", "sysadmin_capability":
				s.UnrestrictedExec++
			case "dangerous_command":
				s.DangerousCommands++
			case "debug_entrypoint", "debug_command", "interactive_mode":
				s.DebugShells++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Process Execution Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Shell access:          %d\n", r.Summary.ShellAccess)
	fmt.Fprintf(&b, "  Unrestricted exec:     %d\n", r.Summary.UnrestrictedExec)
	fmt.Fprintf(&b, "  Dangerous commands:    %d\n", r.Summary.DangerousCommands)
	fmt.Fprintf(&b, "  Debug shells:          %d\n\n", r.Summary.DebugShells)
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
