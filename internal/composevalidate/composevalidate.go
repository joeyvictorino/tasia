package composevalidate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	File     string `json:"file"`
	Service  string `json:"service,omitempty"`
	Field    string `json:"field"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Line     int    `json:"line,omitempty"`
}

type Summary struct {
	FilesChecked   int `json:"files_checked"`
	ServicesFound  int `json:"services_found"`
	TotalFindings  int `json:"total_findings"`
	CriticalCount  int `json:"critical_count"`
	HighCount      int `json:"high_count"`
	MediumCount    int `json:"medium_count"`
	LowCount       int `json:"low_count"`
}

type Report struct {
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings"`
}

func Analyze(c *collect.Collected) Report {
	var findings []Finding

	for _, cf := range c.ComposeFiles {
		findings = append(findings, validateFile(cf)...)
	}

	sort.Slice(findings, func(i, j int) bool {
		return sevRank(findings[i].Severity) > sevRank(findings[j].Severity)
	})

	svcs := 0
	for _, cf := range c.ComposeFiles {
		svcs += len(cf.Services)
	}

	r := Report{
		Summary: Summary{
			FilesChecked:  len(c.ComposeFiles),
			ServicesFound: svcs,
			TotalFindings: len(findings),
		},
		Findings: findings,
	}
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			r.Summary.CriticalCount++
		case "high":
			r.Summary.HighCount++
		case "medium":
			r.Summary.MediumCount++
		case "low":
			r.Summary.LowCount++
		}
	}
	return r
}

func validateFile(cf compose.File) []Finding {
	var findings []Finding

	if len(cf.Services) == 0 {
		findings = append(findings, Finding{
			File:     cf.Path,
			Field:    "services",
			Severity: "high",
			Message:  "compose file has no services defined",
		})
	}

	for _, svc := range cf.Services {
		if svc.Image == "" {
			findings = append(findings, Finding{
				File:     cf.Path,
				Service:  svc.Name,
				Field:    "image",
				Severity: "high",
				Message:  fmt.Sprintf("service %q has no image specified", svc.Name),
				Line:     svc.ImageLine,
			})
		}

		if svc.Image != "" && !strings.Contains(svc.Image, ":") {
			findings = append(findings, Finding{
				File:     cf.Path,
				Service:  svc.Name,
				Field:    "image",
				Severity: "medium",
				Message:  fmt.Sprintf("service %q image %q has no tag (defaults to :latest)", svc.Name, svc.Image),
				Line:     svc.ImageLine,
			})
		}

		if svc.Image != "" && strings.HasSuffix(svc.Image, ":latest") {
			findings = append(findings, Finding{
				File:     cf.Path,
				Service:  svc.Name,
				Field:    "image",
				Severity: "medium",
				Message:  fmt.Sprintf("service %q uses :latest tag (not reproducible)", svc.Name),
				Line:     svc.ImageLine,
			})
		}

		for _, p := range svc.Ports {
			if p.HostIP == "" || p.HostIP == "0.0.0.0" {
				findings = append(findings, Finding{
					File:     cf.Path,
					Service:  svc.Name,
					Field:    "ports",
					Severity: "medium",
					Message:  fmt.Sprintf("service %q port %d bound to all interfaces", svc.Name, p.HostPort),
					Line:     svc.PortsLine,
				})
			}
		}

		if svc.Privileged {
			findings = append(findings, Finding{
				File:     cf.Path,
				Service:  svc.Name,
				Field:    "privileged",
				Severity: "critical",
				Message:  fmt.Sprintf("service %q runs in privileged mode", svc.Name),
				Line:     svc.PrivLine,
			})
		}

		if svc.NetworkMode == "host" {
			findings = append(findings, Finding{
				File:     cf.Path,
				Service:  svc.Name,
				Field:    "network_mode",
				Severity: "high",
				Message:  fmt.Sprintf("service %q uses host network mode", svc.Name),
				Line:     svc.NetworkModeLine,
			})
		}

		for _, v := range svc.Volumes {
			parts := strings.SplitN(v, ":", 2)
			if len(parts) >= 1 {
				src := parts[0]
				if src == "/" || src == "/etc" || src == "/var" || src == "/root" || src == "/home" {
					findings = append(findings, Finding{
						File:     cf.Path,
						Service:  svc.Name,
						Field:    "volumes",
						Severity: "critical",
						Message:  fmt.Sprintf("service %q mounts sensitive host path %q", svc.Name, src),
						Line:     svc.VolumesLine,
					})
				}
			}
		}

		for _, env := range svc.Environment {
			k := strings.SplitN(env, "=", 2)[0]
			kUpper := strings.ToUpper(k)
			if strings.Contains(kUpper, "PASSWORD") || strings.Contains(kUpper, "SECRET") ||
				strings.Contains(kUpper, "API_KEY") || strings.Contains(kUpper, "TOKEN") {
				findings = append(findings, Finding{
					File:     cf.Path,
					Service:  svc.Name,
					Field:    "environment",
					Severity: "high",
					Message:  fmt.Sprintf("service %q has inline secret %q (use secrets or .env)", svc.Name, k),
					Line:     svc.EnvLine,
				})
			}
		}

		if svc.Restart == "" && (svc.DeployRestartPolicy == nil) {
			findings = append(findings, Finding{
				File:     cf.Path,
				Service:  svc.Name,
				Field:    "restart",
				Severity: "low",
				Message:  fmt.Sprintf("service %q has no restart policy", svc.Name),
			})
		}

		if svc.MemLimit == "" && svc.CPUs == "" {
			findings = append(findings, Finding{
				File:     cf.Path,
				Service:  svc.Name,
				Field:    "resources",
				Severity: "low",
				Message:  fmt.Sprintf("service %q has no resource limits (mem_limit/cpus)", svc.Name),
			})
		}
	}

	return findings
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Compose Schema Validation\n")
	b.WriteString(strings.Repeat("=", 62) + "\n\n")

	if r.Summary.FilesChecked == 0 {
		b.WriteString("  No compose files found.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "  Files checked:   %d\n", r.Summary.FilesChecked)
	fmt.Fprintf(&b, "  Services found:  %d\n", r.Summary.ServicesFound)
	fmt.Fprintf(&b, "  Findings:        %d\n", r.Summary.TotalFindings)
	if r.Summary.CriticalCount > 0 {
		fmt.Fprintf(&b, "  Critical:        %d\n", r.Summary.CriticalCount)
	}
	if r.Summary.HighCount > 0 {
		fmt.Fprintf(&b, "  High:            %d\n", r.Summary.HighCount)
	}
	if r.Summary.MediumCount > 0 {
		fmt.Fprintf(&b, "  Medium:          %d\n", r.Summary.MediumCount)
	}
	if r.Summary.LowCount > 0 {
		fmt.Fprintf(&b, "  Low:             %d\n", r.Summary.LowCount)
	}
	b.WriteString("\n")

	if len(r.Findings) > 0 {
		b.WriteString("Findings\n")
		b.WriteString(strings.Repeat("-", 62) + "\n")
		for _, f := range r.Findings {
			loc := f.File
			if f.Service != "" {
				loc += "/" + f.Service
			}
			if f.Line > 0 {
				loc += fmt.Sprintf(":%d", f.Line)
			}
			fmt.Fprintf(&b, "  [%s] %s: %s\n", strings.ToUpper(f.Severity), loc, f.Message)
		}
		b.WriteString("\n")
	}

	return b.String()
}
