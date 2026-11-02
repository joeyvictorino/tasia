package tty

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
	Service   string    `json:"service"`
	File      string    `json:"file"`
	Tty       bool      `json:"tty"`
	StdinOpen bool      `json:"stdin_open"`
	Findings  []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices   int `json:"total_services"`
	TtyEnabled      int `json:"tty_enabled"`
	StdinEnabled    int `json:"stdin_enabled"`
	Interactive     int `json:"interactive"`
	TotalFindings   int `json:"total_findings"`
}

var productionImages = []string{
	"nginx", "postgres", "mysql", "redis", "mongo", "elasticsearch",
	"rabbitmq", "kafka", "minio", "vault", "consul", "traefik",
	"caddy", "prometheus", "grafana", "influxdb",
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
	sr := ServiceResult{
		Service:   svc.Name,
		File:      file,
		Tty:       svc.Tty,
		StdinOpen: svc.StdinOpen,
	}

	if svc.Tty && svc.StdinOpen {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "tty_interactive",
			Message: fmt.Sprintf("service %q has both tty and stdin_open enabled; fully interactive containers increase attack surface", svc.Name),
		})
	} else if svc.Tty {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "tty_enabled",
			Message: fmt.Sprintf("service %q has tty enabled; disable for non-interactive workloads", svc.Name),
		})
	} else if svc.StdinOpen {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "tty_stdin_open",
			Message: fmt.Sprintf("service %q has stdin_open enabled; stdin pipe can be used for container injection", svc.Name),
		})
	}

	if svc.Tty && isProductionService(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "tty_production",
			Message: fmt.Sprintf("production service %q has tty enabled; interactive mode is a development setting", svc.Name),
		})
	}

	if (svc.Tty || svc.StdinOpen) && svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "tty_privileged",
			Message: fmt.Sprintf("privileged service %q has interactive mode; combined with privileged creates escape risk", svc.Name),
		})
	}

	return sr
}

func isProductionService(svc compose.Service) bool {
	img := strings.ToLower(svc.Image)
	for _, prod := range productionImages {
		if strings.Contains(img, prod) {
			return true
		}
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		if sr.Tty {
			s.TtyEnabled++
		}
		if sr.StdinOpen {
			s.StdinEnabled++
		}
		if sr.Tty && sr.StdinOpen {
			s.Interactive++
		}
		s.TotalFindings += len(sr.Findings)
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "TTY / Interactive Container Analysis: %s\n\n", r.Path)
	for _, sr := range r.Services {
		flags := ""
		if sr.Tty {
			flags += " tty=true"
		}
		if sr.StdinOpen {
			flags += " stdin_open=true"
		}
		if flags == "" {
			flags = " (non-interactive)"
		}
		fmt.Fprintf(&b, "  %s%s\n", sr.Service, flags)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s – %s\n", f.Level, f.Rule, f.Message)
		}
	}
	fmt.Fprintf(&b, "\n  Summary: %d services, %d tty, %d stdin, %d fully-interactive, %d findings\n",
		r.Summary.TotalServices, r.Summary.TtyEnabled, r.Summary.StdinEnabled, r.Summary.Interactive, r.Summary.TotalFindings)
	return b.String()
}
