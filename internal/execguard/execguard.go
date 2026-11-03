package execguard

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

type DockerfileResult struct {
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path        string             `json:"path"`
	Services    []ServiceResult    `json:"services"`
	Dockerfiles []DockerfileResult `json:"dockerfiles"`
	Summary     Summary            `json:"summary"`
}

type Summary struct {
	TotalServices     int `json:"total_services"`
	TotalDockerfiles  int `json:"total_dockerfiles"`
	TotalFindings     int `json:"total_findings"`
	ShellFormCmd      int `json:"shell_form_cmd"`
	ShellFormEntry    int `json:"shell_form_entrypoint"`
	PipeInContent     int `json:"pipe_in_content"`
	UnsafeShellExpand int `json:"unsafe_shell_expand"`
	ComposeShellCmd   int `json:"compose_shell_command"`
}

var dangerousShellPatterns = []string{
	"eval ", "$(", "`",
	"&&", "||", "|",
	";",
}

func hasPipeOrChain(content string) bool {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if !strings.HasPrefix(upper, "RUN ") {
			continue
		}
		args := trimmed[4:]
		for _, p := range []string{"|", "&&", "||"} {
			if strings.Contains(args, p) {
				return true
			}
		}
	}
	return false
}

func hasUnsafeShellExpansion(content string) bool {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if !strings.HasPrefix(upper, "RUN ") {
			continue
		}
		args := trimmed[4:]
		if strings.Contains(args, "$(") || strings.Contains(args, "`") {
			return true
		}
	}
	return false
}

func analyzeDockerfile(df collect.Dockerfile) DockerfileResult {
	dr := DockerfileResult{File: df.Path}

	if df.Cmd != "" && !df.CmdExec {
		dr.Findings = append(dr.Findings, Finding{
			Level:   "high",
			Rule:    "shell_form_cmd",
			Message: fmt.Sprintf("CMD uses shell form '%s'; the process runs under /bin/sh -c and will not receive signals (SIGTERM) properly — use exec form [\"...\"]", truncate(df.Cmd, 80)),
		})
	}

	if df.Entrypoint != "" && !df.EntrypointExec {
		dr.Findings = append(dr.Findings, Finding{
			Level:   "high",
			Rule:    "shell_form_entrypoint",
			Message: fmt.Sprintf("ENTRYPOINT uses shell form '%s'; the process runs under /bin/sh -c and will not receive signals properly — use exec form [\"...\"]", truncate(df.Entrypoint, 80)),
		})
	}

	if hasPipeOrChain(df.Content) {
		dr.Findings = append(dr.Findings, Finding{
			Level:   "medium",
			Rule:    "pipe_in_content",
			Message: fmt.Sprintf("Dockerfile '%s' has RUN with pipe/chain; only the last command's exit code is checked — use 'set -o pipefail' or split into separate RUN instructions", df.Path),
		})
	}

	if hasUnsafeShellExpansion(df.Content) {
		dr.Findings = append(dr.Findings, Finding{
			Level:   "medium",
			Rule:    "unsafe_shell_expand",
			Message: fmt.Sprintf("Dockerfile '%s' has RUN with shell expansion ($() or backticks); consider exec form or careful quoting to avoid injection risk", df.Path),
		})
	}

	return dr
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	cmdStr := strings.Join(svc.Command, " ")
	if cmdStr != "" {
		lower := strings.ToLower(cmdStr)
		for _, p := range dangerousShellPatterns {
			if strings.Contains(lower, p) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "compose_shell_command",
					Message: fmt.Sprintf("Service '%s' command contains shell pattern '%s' in '%s'; this may be subject to injection if variables are user-controlled", svc.Name, p, truncate(cmdStr, 80)),
				})
				break
			}
		}
	}

	return sr
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}

	for _, df := range c.Dockerfiles {
		dr := analyzeDockerfile(df)
		r.Dockerfiles = append(r.Dockerfiles, dr)
	}

	r.Summary = summarize(r.Services, r.Dockerfiles)
	return r
}

func summarize(services []ServiceResult, dockerfiles []DockerfileResult) Summary {
	s := Summary{
		TotalServices:    len(services),
		TotalDockerfiles: len(dockerfiles),
	}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			if f.Rule == "compose_shell_command" {
				s.ComposeShellCmd++
			}
		}
	}
	for _, dr := range dockerfiles {
		for _, f := range dr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "shell_form_cmd":
				s.ShellFormCmd++
			case "shell_form_entrypoint":
				s.ShellFormEntry++
			case "pipe_in_content":
				s.PipeInContent++
			case "unsafe_shell_expand":
				s.UnsafeShellExpand++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Exec Form / Shell Form Analysis (%d services, %d dockerfiles, %d findings)\n\n",
		r.Summary.TotalServices, r.Summary.TotalDockerfiles, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Shell form CMD:                %d\n", r.Summary.ShellFormCmd)
	fmt.Fprintf(&b, "  Shell form ENTRYPOINT:         %d\n", r.Summary.ShellFormEntry)
	fmt.Fprintf(&b, "  Pipe in RUN:                   %d\n", r.Summary.PipeInContent)
	fmt.Fprintf(&b, "  Unsafe shell expansion:        %d\n", r.Summary.UnsafeShellExpand)
	fmt.Fprintf(&b, "  Compose shell commands:        %d\n\n", r.Summary.ComposeShellCmd)

	for _, dr := range r.Dockerfiles {
		fmt.Fprintf(&b, "  Dockerfile: %s\n", dr.File)
		if len(dr.Findings) == 0 {
			fmt.Fprintf(&b, "    (no findings)\n")
		}
		for _, f := range dr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}

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
