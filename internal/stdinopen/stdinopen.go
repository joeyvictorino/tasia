package stdinopen

import (
	"encoding/json"
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
	TotalServices     int `json:"total_services"`
	TotalFindings     int `json:"total_findings"`
	StdinOpenCount    int `json:"stdin_open_count"`
	TtyCount          int `json:"tty_count"`
	StdinTtyCombo     int `json:"stdin_tty_combo"`
	PrivilegedStdin   int `json:"privileged_stdin"`
	NetworkHostStdin  int `json:"network_host_stdin"`
	NoUserStdin       int `json:"no_user_stdin"`
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

	if svc.StdinOpen && svc.Tty {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "stdin_tty_combo",
			Message: fmt.Sprintf("Service '%s' has both stdin_open and tty enabled; provides interactive shell access to the container", svc.Name),
		})
	} else if svc.StdinOpen {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "stdin_open_enabled",
			Message: fmt.Sprintf("Service '%s' has stdin_open enabled; allows piping data into the container process", svc.Name),
		})
	}

	if svc.Tty && !svc.StdinOpen {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "tty_without_stdin",
			Message: fmt.Sprintf("Service '%s' has tty enabled without stdin_open; TTY allocated but no stdin attached (unusual)", svc.Name),
		})
	}

	if svc.StdinOpen && svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "stdin_privileged",
			Message: fmt.Sprintf("Service '%s' has stdin_open on a privileged container; enables interactive root access to the host", svc.Name),
		})
	}

	if svc.StdinOpen && svc.NetworkMode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "stdin_network_host",
			Message: fmt.Sprintf("Service '%s' has stdin_open with network_mode:host; interactive access with host network stack", svc.Name),
		})
	}

	if svc.StdinOpen && svc.User == "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "stdin_no_user",
			Message: fmt.Sprintf("Service '%s' has stdin_open without explicit user; may default to root", svc.Name),
		})
	}

	if (svc.StdinOpen || svc.Tty) && hasWritableVolume(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "stdin_writable_volume",
			Message: fmt.Sprintf("Service '%s' has interactive access with writable host volumes; could modify host files interactively", svc.Name),
		})
	}

	if (svc.StdinOpen || svc.Tty) && hasCapabilities(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "stdin_extra_caps",
			Message: fmt.Sprintf("Service '%s' has interactive access with extra capabilities (%s)", svc.Name, strings.Join(svc.CapAdd, ", ")),
		})
	}

	return sr
}

func hasWritableVolume(svc compose.Service) bool {
	for _, v := range svc.Volumes {
		if strings.Contains(v, ":") && !strings.HasSuffix(v, ":ro") {
			return true
		}
	}
	return false
}

func hasCapabilities(svc compose.Service) bool {
	return len(svc.CapAdd) > 0
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "stdin_open_enabled":
				s.StdinOpenCount++
			case "tty_without_stdin":
				s.TtyCount++
			case "stdin_tty_combo":
				s.StdinTtyCombo++
			case "stdin_privileged":
				s.PrivilegedStdin++
			case "stdin_network_host":
				s.NetworkHostStdin++
			case "stdin_no_user":
				s.NoUserStdin++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Stdin/TTY Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  stdin_open enabled:     %d\n", r.Summary.StdinOpenCount)
	fmt.Fprintf(&b, "  tty only:              %d\n", r.Summary.TtyCount)
	fmt.Fprintf(&b, "  stdin+tty combo:       %d\n", r.Summary.StdinTtyCombo)
	fmt.Fprintf(&b, "  privileged+stdin:      %d\n", r.Summary.PrivilegedStdin)
	fmt.Fprintf(&b, "  network_host+stdin:    %d\n", r.Summary.NetworkHostStdin)
	fmt.Fprintf(&b, "  no user+stdin:         %d\n\n", r.Summary.NoUserStdin)
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

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
