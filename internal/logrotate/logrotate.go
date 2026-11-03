package logrotate

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
	NoRotation       int `json:"no_rotation"`
	UnboundedVolume  int `json:"unbounded_volume"`
	StdoutNoDriver   int `json:"stdout_no_driver"`
}

var logVolumePaths = []string{
	"/var/log",
	"/logs",
	"/app/logs",
	"/tmp/logs",
	"/var/lib/docker/containers",
}

func isLogVolume(vol string) bool {
	parts := strings.SplitN(vol, ":", 2)
	if len(parts) < 2 {
		return false
	}
	containerPath := strings.TrimSpace(parts[1])
	containerPath = strings.Split(containerPath, ":")[0]
	lower := strings.ToLower(containerPath)
	for _, lp := range logVolumePaths {
		if lower == lp || strings.HasPrefix(lower, lp+"/") {
			return true
		}
	}
	return strings.Contains(lower, "log")
}

func hasMaxSize(logging *compose.LoggingConfig) bool {
	if logging == nil {
		return false
	}
	for k := range logging.Options {
		if k == "max-size" || k == "max_size" {
			return true
		}
	}
	return false
}

func hasMaxFile(logging *compose.LoggingConfig) bool {
	if logging == nil {
		return false
	}
	for k := range logging.Options {
		if k == "max-file" || k == "max_file" {
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

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if svc.Logging != nil && svc.Logging.Driver != "" && svc.Logging.Driver != "none" {
		if !hasMaxSize(svc.Logging) || !hasMaxFile(svc.Logging) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "logrotate_no_rotation",
				Message: fmt.Sprintf("Service '%s' uses logging driver '%s' without max-size/max-file limits; logs may grow unbounded", svc.Name, svc.Logging.Driver),
			})
		}
	}

	for _, vol := range svc.Volumes {
		if isLogVolume(vol) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "logrotate_unbounded_volume",
				Message: fmt.Sprintf("Service '%s' mounts a log directory volume '%s' without container-level size limits; consider adding log rotation", svc.Name, vol),
			})
		}
	}

	if svc.Logging == nil && len(svc.Ports) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "logrotate_stdout_no_driver",
			Message: fmt.Sprintf("Service '%s' exposes ports but has no explicit logging driver; stdout defaults to json-file with no rotation limits", svc.Name),
		})
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "logrotate_no_rotation":
				s.NoRotation++
			case "logrotate_unbounded_volume":
				s.UnboundedVolume++
			case "logrotate_stdout_no_driver":
				s.StdoutNoDriver++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Log Rotation Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No rotation policy:    %d\n", r.Summary.NoRotation)
	fmt.Fprintf(&b, "  Unbounded log volume:  %d\n", r.Summary.UnboundedVolume)
	fmt.Fprintf(&b, "  Stdout no driver:      %d\n\n", r.Summary.StdoutNoDriver)
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
