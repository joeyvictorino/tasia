package cmdinject

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
	TotalServices    int `json:"total_services"`
	TotalFindings    int `json:"total_findings"`
	ShellForm        int `json:"shell_form"`
	EnvExpansion     int `json:"env_expansion"`
	UnsafeEval       int `json:"unsafe_eval"`
	CurlPipe         int `json:"curl_pipe"`
	WildcardGlob     int `json:"wildcard_glob"`
	SetuidExec       int `json:"setuid_exec"`
}

var shellFormIndicators = []string{
	"/bin/sh -c", "/bin/bash -c", "sh -c", "bash -c",
}

var unsafeEvalPatterns = []string{
	"eval ", "exec ", "source ", ". /",
}

var curlPipePatterns = []string{
	"curl|sh", "curl|bash", "wget|sh", "wget|bash",
	"curl | sh", "curl | bash", "wget | sh", "wget | bash",
	"curl|sh", "wget|sh",
}

func hasCurlPipe(s string) bool {
	lo := strings.ToLower(s)
	for _, p := range curlPipePatterns {
		if strings.Contains(lo, p) {
			return true
		}
	}
	parts := strings.Split(lo, "|")
	if len(parts) < 2 {
		return false
	}
	for i := 0; i < len(parts)-1; i++ {
		left := strings.TrimSpace(parts[i])
		right := strings.TrimSpace(parts[i+1])
		if (strings.Contains(left, "curl") || strings.Contains(left, "wget")) &&
			(strings.HasPrefix(right, "sh") || strings.HasPrefix(right, "bash")) {
			return true
		}
	}
	return false
}

var setuidPatterns = []string{
	"chmod u+s", "chmod +s", "chmod 4", "install -m 4",
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

	checkCmdFields(&sr, svc, svc.Entrypoint, "entrypoint")
	checkCmdFields(&sr, svc, svc.Command, "command")

	return sr
}

func checkCmdFields(sr *ServiceResult, svc compose.Service, args []string, field string) {
	if len(args) == 0 {
		return
	}

	joined := strings.Join(args, " ")
	lower := strings.ToLower(joined)

	if len(args) == 1 && containsAny(lower, shellFormIndicators) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cmd_shell_form",
			Message: fmt.Sprintf("Service '%s' %s uses shell form (%s); shell form is vulnerable to shell injection and prevents signal forwarding", svc.Name, field, truncate(joined, 60)),
		})
	}

	if strings.Contains(joined, "$") || strings.Contains(joined, "${") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "cmd_env_expansion",
			Message: fmt.Sprintf("Service '%s' %s contains unquoted variable expansion; attacker-controlled env vars can inject arbitrary commands", svc.Name, field),
		})
	}

	if containsAny(lower, unsafeEvalPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "cmd_unsafe_eval",
			Message: fmt.Sprintf("Service '%s' %s uses eval/exec/source; dynamic code execution enables injection attacks", svc.Name, field),
		})
	}

	if hasCurlPipe(joined) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "cmd_curl_pipe",
			Message: fmt.Sprintf("Service '%s' %s pipes a remote script to a shell; supply-chain attack vector with no integrity verification", svc.Name, field),
		})
	}

	for _, arg := range args {
		if strings.Contains(arg, "*") || strings.Contains(arg, "?") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "cmd_wildcard_glob",
				Message: fmt.Sprintf("Service '%s' %s uses shell glob pattern '%s'; glob expansion in entrypoints can include unintended files", svc.Name, field, truncate(arg, 40)),
			})
			break
		}
	}

	if containsAny(lower, setuidPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "cmd_setuid_exec",
			Message: fmt.Sprintf("Service '%s' %s sets SUID/SGID bits; privilege escalation risk from within the container", svc.Name, field),
		})
	}
}

func containsAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "cmd_shell_form":
				s.ShellForm++
			case "cmd_env_expansion":
				s.EnvExpansion++
			case "cmd_unsafe_eval":
				s.UnsafeEval++
			case "cmd_curl_pipe":
				s.CurlPipe++
			case "cmd_wildcard_glob":
				s.WildcardGlob++
			case "cmd_setuid_exec":
				s.SetuidExec++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Command Injection Risk Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Shell form usage:       %d\n", r.Summary.ShellForm)
	fmt.Fprintf(&b, "  Env var expansion:      %d\n", r.Summary.EnvExpansion)
	fmt.Fprintf(&b, "  Unsafe eval/exec:       %d\n", r.Summary.UnsafeEval)
	fmt.Fprintf(&b, "  Curl-pipe-shell:        %d\n", r.Summary.CurlPipe)
	fmt.Fprintf(&b, "  Wildcard globs:         %d\n", r.Summary.WildcardGlob)
	fmt.Fprintf(&b, "  SUID/SGID setting:      %d\n\n", r.Summary.SetuidExec)
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
