package ambient

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
	AmbientCaps       int `json:"ambient_caps"`
	NoNewPrivs        int `json:"no_new_privs_missing"`
	DangerousCaps     int `json:"dangerous_caps"`
	CapDropMissing    int `json:"cap_drop_missing"`
}

var dangerousCaps = []string{
	"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
	"SYS_BOOT", "NET_ADMIN", "NET_RAW", "DAC_OVERRIDE",
	"DAC_READ_SEARCH", "SETUID", "SETGID", "FOWNER",
	"MKNOD", "AUDIT_WRITE", "AUDIT_CONTROL",
}

func isDangerous(cap string) bool {
	upper := strings.ToUpper(strings.TrimSpace(cap))
	for _, d := range dangerousCaps {
		if upper == d {
			return true
		}
	}
	return false
}

func hasNoNewPrivileges(opts []string) bool {
	for _, o := range opts {
		lower := strings.ToLower(strings.TrimSpace(o))
		if lower == "no-new-privileges" || lower == "no-new-privileges:true" || lower == "no-new-privileges=true" {
			return true
		}
	}
	return false
}

func hasCapDropAll(caps []string) bool {
	for _, c := range caps {
		if strings.ToUpper(strings.TrimSpace(c)) == "ALL" {
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

	for _, cap := range svc.CapAdd {
		if isDangerous(cap) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "dangerous_cap_added",
				Message: fmt.Sprintf("Service '%s' adds dangerous capability %s; grants elevated kernel access that could enable container escape", svc.Name, strings.ToUpper(cap)),
			})
		}
	}

	if len(svc.CapAdd) > 0 && !hasNoNewPrivileges(svc.SecurityOpt) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "no_new_privs_missing",
			Message: fmt.Sprintf("Service '%s' adds capabilities but lacks no-new-privileges security option; child processes may gain additional privileges", svc.Name),
		})
	}

	if len(svc.CapAdd) > 0 && !hasCapDropAll(svc.CapDrop) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cap_drop_missing",
			Message: fmt.Sprintf("Service '%s' adds capabilities without first dropping ALL; ambient capabilities may remain from the base set", svc.Name),
		})
	}

	if len(svc.CapAdd) > 5 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "excessive_caps",
			Message: fmt.Sprintf("Service '%s' adds %d capabilities; consider using --privileged audit or dropping to minimum required set", svc.Name, len(svc.CapAdd)),
		})
	}

	if svc.Privileged && len(svc.CapDrop) > 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "privileged_with_cap_drop",
			Message: fmt.Sprintf("Service '%s' is privileged but attempts to drop capabilities; cap_drop is ignored in privileged mode", svc.Name),
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
			case "dangerous_cap_added", "excessive_caps":
				s.DangerousCaps++
			case "no_new_privs_missing":
				s.NoNewPrivs++
			case "cap_drop_missing":
				s.CapDropMissing++
			case "privileged_with_cap_drop":
				s.AmbientCaps++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Ambient Capability Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Dangerous caps:        %d\n", r.Summary.DangerousCaps)
	fmt.Fprintf(&b, "  No-new-privs missing:  %d\n", r.Summary.NoNewPrivs)
	fmt.Fprintf(&b, "  Cap drop missing:      %d\n", r.Summary.CapDropMissing)
	fmt.Fprintf(&b, "  Ambient cap issues:    %d\n\n", r.Summary.AmbientCaps)
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
