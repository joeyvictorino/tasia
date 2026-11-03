package securityopt

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
	TotalServices       int `json:"total_services"`
	TotalFindings       int `json:"total_findings"`
	SeccompDisabled     int `json:"seccomp_disabled"`
	AppArmorDisabled    int `json:"apparmor_disabled"`
	SELinuxDisabled     int `json:"selinux_disabled"`
	NoSecurityOpts      int `json:"no_security_opts"`
}

func isSeccompDisabled(opt string) bool {
	lower := strings.ToLower(strings.TrimSpace(opt))
	return lower == "seccomp=unconfined" || lower == "seccomp:unconfined"
}

func isAppArmorDisabled(opt string) bool {
	lower := strings.ToLower(strings.TrimSpace(opt))
	return lower == "apparmor=unconfined" || lower == "apparmor:unconfined"
}

func isSELinuxDisabled(opt string) bool {
	lower := strings.ToLower(strings.TrimSpace(opt))
	return lower == "label=disable" || lower == "label:disable"
}

func hasSeccompProfile(opts []string) bool {
	for _, o := range opts {
		lower := strings.ToLower(strings.TrimSpace(o))
		if strings.HasPrefix(lower, "seccomp=") || strings.HasPrefix(lower, "seccomp:") {
			return true
		}
	}
	return false
}

func hasAppArmorProfile(opts []string) bool {
	for _, o := range opts {
		lower := strings.ToLower(strings.TrimSpace(o))
		if strings.HasPrefix(lower, "apparmor=") || strings.HasPrefix(lower, "apparmor:") {
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

	for _, opt := range svc.SecurityOpt {
		if isSeccompDisabled(opt) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "seccomp_disabled",
				Message: fmt.Sprintf("Service '%s' disables seccomp filtering (seccomp=unconfined); all syscalls are allowed, enabling container escape vectors", svc.Name),
			})
		}
		if isAppArmorDisabled(opt) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "apparmor_disabled",
				Message: fmt.Sprintf("Service '%s' disables AppArmor (apparmor=unconfined); mandatory access controls are bypassed", svc.Name),
			})
		}
		if isSELinuxDisabled(opt) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "selinux_disabled",
				Message: fmt.Sprintf("Service '%s' disables SELinux labeling (label=disable); mandatory access controls are bypassed", svc.Name),
			})
		}
	}

	if len(svc.SecurityOpt) == 0 && !svc.Privileged {
		if len(svc.CapAdd) > 0 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "no_security_opts",
				Message: fmt.Sprintf("Service '%s' adds capabilities but has no security_opt configured; consider adding seccomp and apparmor profiles", svc.Name),
			})
		}
	}

	if svc.Privileged && !hasSeccompProfile(svc.SecurityOpt) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "privileged_no_seccomp",
			Message: fmt.Sprintf("Service '%s' is privileged without explicit seccomp profile; all syscalls are available", svc.Name),
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
			case "seccomp_disabled":
				s.SeccompDisabled++
			case "apparmor_disabled":
				s.AppArmorDisabled++
			case "selinux_disabled":
				s.SELinuxDisabled++
			case "no_security_opts":
				s.NoSecurityOpts++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Security Options Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Seccomp disabled:      %d\n", r.Summary.SeccompDisabled)
	fmt.Fprintf(&b, "  AppArmor disabled:     %d\n", r.Summary.AppArmorDisabled)
	fmt.Fprintf(&b, "  SELinux disabled:      %d\n", r.Summary.SELinuxDisabled)
	fmt.Fprintf(&b, "  No security opts:      %d\n\n", r.Summary.NoSecurityOpts)
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
