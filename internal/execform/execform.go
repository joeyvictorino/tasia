package execform

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
	TotalServices    int `json:"total_services"`
	TotalDockerfiles int `json:"total_dockerfiles"`
	TotalFindings    int `json:"total_findings"`
	ShellForm        int `json:"shell_form"`
	NoSignalHandling int `json:"no_signal_handling"`
}

func isShellForm(cmd string) bool {
	trimmed := strings.TrimSpace(cmd)
	if trimmed == "" {
		return false
	}
	return !strings.HasPrefix(trimmed, "[")
}

func analyzeService(svc compose.Service, composePath string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: composePath}

	if len(svc.Entrypoint) == 1 && isShellForm(svc.Entrypoint[0]) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "warning",
			Rule:    "shell_form_entrypoint",
			Message: fmt.Sprintf("service %q uses shell-form entrypoint — signals may not reach the process", svc.Name),
		})
	}

	if len(svc.Command) == 1 && isShellForm(svc.Command[0]) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "shell_form_command",
			Message: fmt.Sprintf("service %q uses shell-form command", svc.Name),
		})
	}

	return sr
}

func analyzeDockerfile(df collect.Dockerfile) DockerfileResult {
	dr := DockerfileResult{File: df.Path}

	if df.Entrypoint != "" && !df.EntrypointExec {
		dr.Findings = append(dr.Findings, Finding{
			Level:   "warning",
			Rule:    "dockerfile_shell_entrypoint",
			Message: fmt.Sprintf("Dockerfile %s uses shell-form ENTRYPOINT — PID 1 is /bin/sh, signals won't propagate", df.Path),
		})
	}

	if df.Cmd != "" && !df.CmdExec {
		dr.Findings = append(dr.Findings, Finding{
			Level:   "info",
			Rule:    "dockerfile_shell_cmd",
			Message: fmt.Sprintf("Dockerfile %s uses shell-form CMD", df.Path),
		})
	}

	return dr
}

func Analyze(c *collect.Collected) Report {
	var services []ServiceResult
	var dockerfiles []DockerfileResult

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			services = append(services, sr)
		}
	}

	for _, df := range c.Dockerfiles {
		dr := analyzeDockerfile(df)
		dockerfiles = append(dockerfiles, dr)
	}

	return Report{
		Path:        c.Root,
		Services:    services,
		Dockerfiles: dockerfiles,
		Summary:     summarize(services, dockerfiles),
	}
}

func summarize(services []ServiceResult, dockerfiles []DockerfileResult) Summary {
	s := Summary{
		TotalServices:    len(services),
		TotalDockerfiles: len(dockerfiles),
	}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "shell_form_entrypoint":
				s.ShellForm++
				s.NoSignalHandling++
			case "shell_form_command":
				s.ShellForm++
			}
		}
	}
	for _, dr := range dockerfiles {
		for _, f := range dr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "dockerfile_shell_entrypoint":
				s.ShellForm++
				s.NoSignalHandling++
			case "dockerfile_shell_cmd":
				s.ShellForm++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Exec Form Analysis\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	b.WriteString(fmt.Sprintf("Root: %s\n", r.Path))
	b.WriteString(fmt.Sprintf("Services: %d  Dockerfiles: %d  Findings: %d\n\n",
		r.Summary.TotalServices, r.Summary.TotalDockerfiles, r.Summary.TotalFindings))

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("Service: %s (%s)\n", sr.Service, sr.File))
		for _, f := range sr.Findings {
			b.WriteString(fmt.Sprintf("  [%s] %s: %s\n", f.Level, f.Rule, f.Message))
		}
		b.WriteString("\n")
	}

	for _, dr := range r.Dockerfiles {
		if len(dr.Findings) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("Dockerfile: %s\n", dr.File))
		for _, f := range dr.Findings {
			b.WriteString(fmt.Sprintf("  [%s] %s: %s\n", f.Level, f.Rule, f.Message))
		}
		b.WriteString("\n")
	}

	return b.String()
}
