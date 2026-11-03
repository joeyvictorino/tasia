package healthz

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
	TotalServices   int `json:"total_services"`
	TotalFindings   int `json:"total_findings"`
	NoCheck         int `json:"no_check"`
	ShellInjection  int `json:"shell_injection"`
	ShortInterval   int `json:"short_interval"`
	NoRetries       int `json:"no_retries"`
}

func hasShellExpansion(cmd string) bool {
	return strings.ContainsAny(cmd, "|&;`$") || strings.Contains(cmd, "$(")
}

func parseInterval(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	var total int
	for _, part := range strings.Fields(s) {
		if strings.HasSuffix(part, "s") {
			val := strings.TrimSuffix(part, "s")
			n := 0
			for _, c := range val {
				if c >= '0' && c <= '9' {
					n = n*10 + int(c-'0')
				}
			}
			total += n
		} else if strings.HasSuffix(part, "m") {
			val := strings.TrimSuffix(part, "m")
			n := 0
			for _, c := range val {
				if c >= '0' && c <= '9' {
					n = n*10 + int(c-'0')
				}
			}
			total += n * 60
		} else {
			n := 0
			for _, c := range part {
				if c >= '0' && c <= '9' {
					n = n*10 + int(c-'0')
				}
			}
			if n > 0 {
				total += n
			}
		}
	}
	return total
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

	if svc.Healthcheck == nil {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "healthz_no_check",
			Message: fmt.Sprintf("Service '%s' has no healthcheck defined; container failures may go undetected", svc.Name),
		})
		return sr
	}

	hc := svc.Healthcheck

	for _, part := range hc.Test {
		if hasShellExpansion(part) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "healthz_shell_injection",
				Message: fmt.Sprintf("Service '%s' healthcheck command contains shell expansion or pipes which could be exploited", svc.Name),
			})
			break
		}
	}

	if hc.Interval != "" {
		secs := parseInterval(hc.Interval)
		if secs > 0 && secs < 5 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "healthz_short_interval",
				Message: fmt.Sprintf("Service '%s' healthcheck interval is %s (<%ds); very frequent checks may impact performance", svc.Name, hc.Interval, secs),
			})
		}
	}

	if hc.Retries == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "healthz_no_retries",
			Message: fmt.Sprintf("Service '%s' healthcheck has no retries configured; a single failure will mark the container unhealthy", svc.Name),
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
			case "healthz_no_check":
				s.NoCheck++
			case "healthz_shell_injection":
				s.ShellInjection++
			case "healthz_short_interval":
				s.ShortInterval++
			case "healthz_no_retries":
				s.NoRetries++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Health Check Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No healthcheck:       %d\n", r.Summary.NoCheck)
	fmt.Fprintf(&b, "  Shell injection risk:  %d\n", r.Summary.ShellInjection)
	fmt.Fprintf(&b, "  Short interval:       %d\n", r.Summary.ShortInterval)
	fmt.Fprintf(&b, "  No retries:           %d\n\n", r.Summary.NoRetries)
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
