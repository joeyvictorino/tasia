package nonroot

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
	RunAsRoot        int `json:"run_as_root"`
	NoUserSet        int `json:"no_user_set"`
	PrivilegedRoot   int `json:"privileged_root"`
}

func isRootUser(user string) bool {
	u := strings.TrimSpace(strings.ToLower(user))
	return u == "root" || u == "0" || strings.HasPrefix(u, "0:")
}

func analyzeService(svc compose.Service, composePath string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: composePath}

	if svc.User == "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "warning",
			Rule:    "no_user_directive",
			Message: fmt.Sprintf("service %q has no user directive — defaults to root", svc.Name),
		})
	} else if isRootUser(svc.User) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "warning",
			Rule:    "explicit_root_user",
			Message: fmt.Sprintf("service %q explicitly runs as root", svc.Name),
		})
	}

	if svc.Privileged && (svc.User == "" || isRootUser(svc.User)) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "error",
			Rule:    "privileged_root",
			Message: fmt.Sprintf("service %q runs privileged as root — full host access", svc.Name),
		})
	}

	return sr
}

func analyzeDockerfile(df collect.Dockerfile) DockerfileResult {
	dr := DockerfileResult{File: df.Path}

	if df.User == "" {
		dr.Findings = append(dr.Findings, Finding{
			Level:   "warning",
			Rule:    "dockerfile_no_user",
			Message: fmt.Sprintf("Dockerfile %s has no USER directive — container runs as root", df.Path),
		})
	} else if isRootUser(df.User) {
		dr.Findings = append(dr.Findings, Finding{
			Level:   "warning",
			Rule:    "dockerfile_root_user",
			Message: fmt.Sprintf("Dockerfile %s sets USER to root", df.Path),
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
			case "explicit_root_user":
				s.RunAsRoot++
			case "no_user_directive":
				s.NoUserSet++
			case "privileged_root":
				s.PrivilegedRoot++
			}
		}
	}
	for _, dr := range dockerfiles {
		for _, f := range dr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "dockerfile_root_user":
				s.RunAsRoot++
			case "dockerfile_no_user":
				s.NoUserSet++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Non-Root User Analysis\n")
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
