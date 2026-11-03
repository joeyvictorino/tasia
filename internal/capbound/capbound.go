package capbound

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
	TotalServices       int `json:"total_services"`
	TotalFindings       int `json:"total_findings"`
	DangerousCaps       int `json:"dangerous_caps"`
	BroadGrants         int `json:"broad_grants"`
	MissingDrops        int `json:"missing_drops"`
	DangerousCombos     int `json:"dangerous_combos"`
	NoCapDropAll        int `json:"no_cap_drop_all"`
}

var dangerousCaps = map[string]string{
	"SYS_ADMIN":   "near-root access; mount, namespace, BPF control",
	"SYS_PTRACE":  "debug any process; read memory, inject code",
	"SYS_RAWIO":   "raw I/O port access; can modify kernel memory",
	"SYS_MODULE":  "load/unload kernel modules",
	"DAC_READ_SEARCH": "bypass file read permissions",
	"NET_ADMIN":   "full network configuration; iptables, routing, interfaces",
	"NET_RAW":     "raw sockets; packet sniffing, spoofing",
	"SYS_BOOT":    "reboot the system",
	"SYS_TIME":    "modify system clock; can break log integrity",
	"MKNOD":       "create device special files",
	"AUDIT_WRITE": "write to kernel audit log",
	"SETUID":      "change process UID",
	"SETGID":      "change process GID",
}

var dangerousCombinations = [][2]string{
	{"SYS_ADMIN", "NET_ADMIN"},
	{"SYS_ADMIN", "SYS_PTRACE"},
	{"SYS_ADMIN", "NET_RAW"},
	{"SYS_PTRACE", "NET_RAW"},
	{"SYS_ADMIN", "SYS_MODULE"},
	{"DAC_READ_SEARCH", "NET_RAW"},
	{"SETUID", "SYS_ADMIN"},
}

var defaultCaps = map[string]bool{
	"CHOWN":          true,
	"DAC_OVERRIDE":   true,
	"FSETID":         true,
	"FOWNER":         true,
	"MKNOD":          true,
	"NET_RAW":        true,
	"SETGID":         true,
	"SETUID":         true,
	"SETFCAP":        true,
	"SETPCAP":        true,
	"NET_BIND_SERVICE": true,
	"SYS_CHROOT":    true,
	"KILL":           true,
	"AUDIT_WRITE":   true,
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

	capSet := normalizeCaps(svc.CapAdd)
	dropSet := normalizeCaps(svc.CapDrop)

	if contains(capSet, "ALL") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "capbound_broad_grant",
			Message: fmt.Sprintf("Service '%s' grants ALL capabilities; equivalent to running privileged", svc.Name),
		})
	}

	for _, cap := range capSet {
		if cap == "ALL" {
			continue
		}
		if desc, ok := dangerousCaps[cap]; ok {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "capbound_dangerous_cap",
				Message: fmt.Sprintf("Service '%s' adds dangerous capability CAP_%s: %s", svc.Name, cap, desc),
			})
		}
	}

	if len(svc.CapAdd) > 0 && !contains(dropSet, "ALL") && len(svc.CapDrop) == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "capbound_missing_drop",
			Message: fmt.Sprintf("Service '%s' adds capabilities without dropping any; consider 'cap_drop: [ALL]' first, then add only needed caps", svc.Name),
		})
	}

	if len(svc.CapAdd) == 0 && len(svc.CapDrop) == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "capbound_no_cap_drop_all",
			Message: fmt.Sprintf("Service '%s' has no cap_drop; runs with Docker default capabilities including NET_RAW and MKNOD", svc.Name),
		})
	}

	effectiveCaps := buildEffectiveSet(capSet, dropSet)
	for _, combo := range dangerousCombinations {
		if effectiveCaps[combo[0]] && effectiveCaps[combo[1]] {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "capbound_dangerous_combo",
				Message: fmt.Sprintf("Service '%s' has dangerous capability combination CAP_%s + CAP_%s", svc.Name, combo[0], combo[1]),
			})
		}
	}

	return sr
}

func normalizeCaps(caps []string) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		c = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CAP_")
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

func contains(caps []string, target string) bool {
	for _, c := range caps {
		if c == target {
			return true
		}
	}
	return false
}

func buildEffectiveSet(add, drop []string) map[string]bool {
	effective := make(map[string]bool)

	if contains(drop, "ALL") {
		for _, c := range add {
			effective[c] = true
		}
		return effective
	}

	for c := range defaultCaps {
		effective[c] = true
	}
	for _, c := range add {
		if c == "ALL" {
			for k := range dangerousCaps {
				effective[k] = true
			}
			for k := range defaultCaps {
				effective[k] = true
			}
		} else {
			effective[c] = true
		}
	}
	for _, c := range drop {
		delete(effective, c)
	}
	return effective
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "capbound_dangerous_cap":
				s.DangerousCaps++
			case "capbound_broad_grant":
				s.BroadGrants++
			case "capbound_missing_drop":
				s.MissingDrops++
			case "capbound_dangerous_combo":
				s.DangerousCombos++
			case "capbound_no_cap_drop_all":
				s.NoCapDropAll++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Capability Bounding Set Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Dangerous capabilities:  %d\n", r.Summary.DangerousCaps)
	fmt.Fprintf(&b, "  Broad grants (ALL):      %d\n", r.Summary.BroadGrants)
	fmt.Fprintf(&b, "  Missing cap_drop:        %d\n", r.Summary.MissingDrops)
	fmt.Fprintf(&b, "  Dangerous combos:        %d\n", r.Summary.DangerousCombos)
	fmt.Fprintf(&b, "  No cap_drop at all:      %d\n\n", r.Summary.NoCapDropAll)
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
