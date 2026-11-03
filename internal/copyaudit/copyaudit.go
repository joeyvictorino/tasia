package copyaudit

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type Finding struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type DockerfileResult struct {
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path        string             `json:"path"`
	Dockerfiles []DockerfileResult `json:"dockerfiles"`
	Summary     Summary            `json:"summary"`
}

type Summary struct {
	TotalDockerfiles int `json:"total_dockerfiles"`
	TotalFindings    int `json:"total_findings"`
	AddURL           int `json:"add_url"`
	AddSensitiveDest int `json:"add_sensitive_dest"`
	AddAsRoot        int `json:"add_as_root"`
}

var sensitivePaths = []string{
	"/etc/", "/root/", "/var/run/",
	"/proc/", "/sys/", "/dev/",
	"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
}

func isSensitiveDest(dest string) bool {
	lower := strings.ToLower(strings.TrimSpace(dest))
	for _, p := range sensitivePaths {
		if strings.HasPrefix(lower, p) || lower == strings.TrimSuffix(p, "/") {
			return true
		}
	}
	return false
}

func analyzeDockerfile(df collect.Dockerfile) DockerfileResult {
	dr := DockerfileResult{File: df.Path}

	for _, add := range df.Adds {
		if add.IsURL {
			dr.Findings = append(dr.Findings, Finding{
				Level:   "warning",
				Rule:    "add_url_source",
				Message: fmt.Sprintf("Dockerfile %s ADD uses URL source %q — prefer COPY + curl for verifiable downloads", df.Path, add.Source),
			})
		}

		if isSensitiveDest(add.Dest) {
			dr.Findings = append(dr.Findings, Finding{
				Level:   "warning",
				Rule:    "add_sensitive_dest",
				Message: fmt.Sprintf("Dockerfile %s ADD copies to sensitive path %q", df.Path, add.Dest),
			})
		}
	}

	if len(df.Adds) > 0 && df.User == "" {
		dr.Findings = append(dr.Findings, Finding{
			Level:   "info",
			Rule:    "add_as_root",
			Message: fmt.Sprintf("Dockerfile %s uses ADD without a USER directive — files are owned by root", df.Path),
		})
	}

	return dr
}

func Analyze(c *collect.Collected) Report {
	var dockerfiles []DockerfileResult

	for _, df := range c.Dockerfiles {
		dr := analyzeDockerfile(df)
		dockerfiles = append(dockerfiles, dr)
	}

	return Report{
		Path:        c.Root,
		Dockerfiles: dockerfiles,
		Summary:     summarize(dockerfiles),
	}
}

func summarize(dockerfiles []DockerfileResult) Summary {
	s := Summary{
		TotalDockerfiles: len(dockerfiles),
	}
	for _, dr := range dockerfiles {
		for _, f := range dr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "add_url_source":
				s.AddURL++
			case "add_sensitive_dest":
				s.AddSensitiveDest++
			case "add_as_root":
				s.AddAsRoot++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("COPY/ADD Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	b.WriteString(fmt.Sprintf("Root: %s\n", r.Path))
	b.WriteString(fmt.Sprintf("Dockerfiles: %d  Findings: %d\n\n",
		r.Summary.TotalDockerfiles, r.Summary.TotalFindings))

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
