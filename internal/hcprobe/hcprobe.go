package hcprobe

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
	TotalServices  int `json:"total_services"`
	TotalFindings  int `json:"total_findings"`
	MissingProbe   int `json:"missing_probe"`
	LongInterval   int `json:"long_interval"`
	NoRetries      int `json:"no_retries"`
	DisabledProbe  int `json:"disabled_probe"`
	ShortTimeout   int `json:"short_timeout"`
}

func analyzeService(svc compose.Service, composePath string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: composePath}

	if svc.Healthcheck == nil {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "warning",
			Rule:    "missing_healthcheck",
			Message: fmt.Sprintf("service %q has no healthcheck — container orchestrator cannot detect failures", svc.Name),
		})
		return sr
	}

	hc := svc.Healthcheck

	if hc.Disable {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "warning",
			Rule:    "disabled_healthcheck",
			Message: fmt.Sprintf("service %q healthcheck is explicitly disabled", svc.Name),
		})
		return sr
	}

	if isLongInterval(hc.Interval) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "long_interval",
			Message: fmt.Sprintf("service %q healthcheck interval %q may delay failure detection", svc.Name, hc.Interval),
		})
	}

	if hc.Retries == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "no_retries",
			Message: fmt.Sprintf("service %q healthcheck has no retries set — single failure marks unhealthy", svc.Name),
		})
	}

	if isShortTimeout(hc.Timeout) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "short_timeout",
			Message: fmt.Sprintf("service %q healthcheck timeout %q may cause false positives", svc.Name, hc.Timeout),
		})
	}

	return sr
}

func isLongInterval(interval string) bool {
	if interval == "" {
		return false
	}
	lower := strings.ToLower(interval)
	if strings.Contains(lower, "m") && !strings.HasPrefix(lower, "0") {
		return true
	}
	if strings.HasSuffix(lower, "s") {
		val := strings.TrimSuffix(lower, "s")
		n := 0
		for _, c := range val {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		return n >= 60
	}
	return false
}

func isShortTimeout(timeout string) bool {
	if timeout == "" {
		return false
	}
	lower := strings.ToLower(timeout)
	if strings.HasSuffix(lower, "s") {
		val := strings.TrimSuffix(lower, "s")
		if val == "1" || val == "2" {
			return true
		}
	}
	return false
}

func Analyze(c *collect.Collected) Report {
	var services []ServiceResult

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			services = append(services, sr)
		}
	}

	return Report{
		Path:     c.Root,
		Services: services,
		Summary:  summarize(services),
	}
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "missing_healthcheck":
				s.MissingProbe++
			case "long_interval":
				s.LongInterval++
			case "no_retries":
				s.NoRetries++
			case "disabled_healthcheck":
				s.DisabledProbe++
			case "short_timeout":
				s.ShortTimeout++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Healthcheck Probe Analysis\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	b.WriteString(fmt.Sprintf("Root: %s\n", r.Path))
	b.WriteString(fmt.Sprintf("Services: %d  Findings: %d\n\n",
		r.Summary.TotalServices, r.Summary.TotalFindings))

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

	return b.String()
}
