package privileged

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service     string `json:"service"`
	Source      string `json:"source"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Line        int    `json:"line,omitempty"`
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Service    string   `json:"service"`
	Source     string   `json:"source"`
	Image      string   `json:"image,omitempty"`
	Privileged bool     `json:"privileged"`
	CapAdd     []string `json:"cap_add,omitempty"`
	CapDrop    []string `json:"cap_drop,omitempty"`
	ReadOnly   bool     `json:"read_only"`
	Findings   []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices   int `json:"total_services"`
	PrivilegedCount int `json:"privileged_count"`
	NoCapDropAll    int `json:"no_cap_drop_all"`
	ReadWriteRoot   int `json:"read_write_root"`
	TotalFindings   int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var dangerousCaps = map[string]string{
	"SYS_ADMIN":    "critical",
	"SYS_MODULE":   "critical",
	"SYS_RAWIO":    "critical",
	"ALL":          "critical",
	"SYS_PTRACE":   "high",
	"NET_ADMIN":    "high",
	"NET_RAW":      "high",
	"DAC_OVERRIDE": "high",
	"SYS_CHROOT":   "medium",
	"SETUID":       "medium",
	"SETGID":       "medium",
	"MKNOD":        "medium",
}

func Analyze(collected *collect.Collected) Report {
	var services []ServiceResult
	var s Summary

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(cf.Path, svc)
			s.TotalServices++
			if sr.Privileged {
				s.PrivilegedCount++
			}
			if !hasDropAll(svc.CapDrop) && !svc.Privileged {
				s.NoCapDropAll++
			}
			if !svc.ReadOnly {
				s.ReadWriteRoot++
			}
			s.TotalFindings += len(sr.Findings)
			services = append(services, sr)
		}
	}

	return Report{Services: services, Summary: s}
}

func analyzeService(path string, svc compose.Service) ServiceResult {
	sr := ServiceResult{
		Service:    svc.Name,
		Source:     path,
		Image:      svc.Image,
		Privileged: svc.Privileged,
		CapAdd:     svc.CapAdd,
		CapDrop:    svc.CapDrop,
		ReadOnly:   svc.ReadOnly,
	}

	if svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			Source:      path,
			RuleID:      "privileged_mode",
			Severity:    "critical",
			Detail:      "container runs in privileged mode, disabling all Linux security modules",
			Line:        svc.PrivLine,
			Remediation: "Remove privileged: true and use specific cap_add entries for required capabilities",
		})
	}

	for _, cap := range svc.CapAdd {
		upper := strings.ToUpper(strings.TrimSpace(cap))
		if sev, ok := dangerousCaps[upper]; ok {
			sr.Findings = append(sr.Findings, Finding{
				Service:     svc.Name,
				Source:      path,
				RuleID:      "dangerous_cap_add",
				Severity:    sev,
				Detail:      fmt.Sprintf("dangerous capability %s added to container", upper),
				Line:        svc.CapAddLine,
				Remediation: fmt.Sprintf("Remove %s from cap_add unless absolutely required; prefer minimal capabilities", upper),
			})
		}
	}

	if !svc.Privileged && !hasDropAll(svc.CapDrop) {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			Source:      path,
			RuleID:      "no_cap_drop_all",
			Severity:    "medium",
			Detail:      "container does not drop all capabilities; default Docker set may be too permissive",
			Line:        svc.CapDropLine,
			Remediation: "Add cap_drop: [ALL] and selectively add back only required capabilities with cap_add",
		})
	}

	if !svc.ReadOnly && !svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			Source:      path,
			RuleID:      "read_write_rootfs",
			Severity:    "low",
			Detail:      "container filesystem is writable; compromised processes can modify binaries",
			Line:        svc.ReadOnlyLine,
			Remediation: "Set read_only: true and use tmpfs or volumes for writable paths",
		})
	}

	return sr
}

func hasDropAll(caps []string) bool {
	for _, c := range caps {
		if strings.EqualFold(c, "ALL") {
			return true
		}
	}
	return false
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Privileged Mode Analysis\n")
	b.WriteString(strings.Repeat("=", 62) + "\n\n")

	fmt.Fprintf(&b, "  Services analyzed:     %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Privileged mode:       %d\n", r.Summary.PrivilegedCount)
	fmt.Fprintf(&b, "  Missing cap_drop ALL:  %d\n", r.Summary.NoCapDropAll)
	fmt.Fprintf(&b, "  Read-write rootfs:     %d\n", r.Summary.ReadWriteRoot)
	fmt.Fprintf(&b, "  Total findings:        %d\n\n", r.Summary.TotalFindings)

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%s)\n", sr.Service, sr.Source)
		for _, f := range sr.Findings {
			sev := strings.ToUpper(f.Severity)
			if f.Line > 0 {
				fmt.Fprintf(&b, "    [%s] line %d: %s (%s)\n", sev, f.Line, f.Detail, f.RuleID)
			} else {
				fmt.Fprintf(&b, "    [%s] %s (%s)\n", sev, f.Detail, f.RuleID)
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}
