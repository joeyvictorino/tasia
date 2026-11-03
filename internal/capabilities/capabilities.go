package capabilities

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

var dangerousCaps = map[string]Severity{
	"SYS_ADMIN":  SevCritical,
	"SYS_PTRACE": SevHigh,
	"NET_ADMIN":  SevHigh,
	"NET_RAW":    SevHigh,
	"DAC_OVERRIDE": SevMedium,
	"SETUID":     SevMedium,
	"SETGID":     SevMedium,
	"SYS_MODULE": SevCritical,
	"SYS_RAWIO":  SevCritical,
	"SYS_CHROOT": SevMedium,
	"MKNOD":      SevMedium,
	"AUDIT_WRITE": SevMedium,
	"ALL":        SevCritical,
}

var defaultDropCaps = []string{
	"ALL",
}

type Finding struct {
	Service     string   `json:"service"`
	Source      string   `json:"source"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Line        int      `json:"line,omitempty"`
	Caps        []string `json:"caps,omitempty"`
}

type ServiceProfile struct {
	Service      string   `json:"service"`
	Source       string   `json:"source"`
	Image        string   `json:"image,omitempty"`
	Privileged   bool     `json:"privileged"`
	CapAdd       []string `json:"cap_add,omitempty"`
	CapDrop      []string `json:"cap_drop,omitempty"`
	SecurityOpts []string `json:"security_opts,omitempty"`
	HasSeccomp   bool     `json:"has_seccomp"`
	RunAsRoot    bool     `json:"run_as_root"`
}

type Report struct {
	Profiles []ServiceProfile `json:"profiles"`
	Findings []Finding        `json:"findings"`
	Summary  Summary          `json:"summary"`
}

type Summary struct {
	TotalServices     int            `json:"total_services"`
	PrivilegedCount   int            `json:"privileged_count"`
	NoSeccompCount    int            `json:"no_seccomp_count"`
	DangerousCapCount int            `json:"dangerous_cap_count"`
	BySeverity        map[string]int `json:"by_severity"`
}

func Analyze(col *collect.Collected) Report {
	var profiles []ServiceProfile
	var findings []Finding

	for _, cf := range col.ComposeFiles {
		for _, svc := range cf.Services {
			p, ff := analyzeComposeService(cf.Path, svc)
			profiles = append(profiles, p)
			findings = append(findings, ff...)
		}
	}

	for _, km := range col.KubeManifests {
		for _, kc := range km.Containers {
			p, ff := analyzeKubeContainer(km.Path, kc)
			profiles = append(profiles, p)
			findings = append(findings, ff...)
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return sevRank(findings[i].Severity) < sevRank(findings[j].Severity)
	})

	return Report{
		Profiles: profiles,
		Findings: findings,
		Summary:  summarize(profiles, findings),
	}
}

func analyzeComposeService(path string, svc compose.Service) (ServiceProfile, []Finding) {
	prof := ServiceProfile{
		Service:      svc.Name,
		Source:       path,
		Image:        svc.Image,
		Privileged:   svc.Privileged,
		CapAdd:       svc.CapAdd,
		CapDrop:      svc.CapDrop,
		SecurityOpts: svc.SecurityOpt,
		HasSeccomp:   hasSeccomp(svc.SecurityOpt),
		RunAsRoot:    false,
	}

	var findings []Finding

	if svc.Privileged {
		findings = append(findings, Finding{
			Service:     svc.Name,
			Source:      path,
			Severity:    SevCritical,
			Category:    "privileged",
			Description: "container runs in privileged mode, bypassing all Linux security",
			Line:        svc.PrivLine,
		})
	}

	dangerous := filterDangerous(svc.CapAdd)
	if len(dangerous) > 0 {
		sev := worstSeverity(dangerous)
		findings = append(findings, Finding{
			Service:     svc.Name,
			Source:      path,
			Severity:    sev,
			Category:    "dangerous_capability",
			Description: fmt.Sprintf("dangerous capabilities added: %s", strings.Join(dangerous, ", ")),
			Line:        svc.CapAddLine,
			Caps:        dangerous,
		})
	}

	if !svc.Privileged && !hasDropAll(svc.CapDrop) {
		findings = append(findings, Finding{
			Service:     svc.Name,
			Source:      path,
			Severity:    SevMedium,
			Category:    "no_cap_drop_all",
			Description: "container does not drop all capabilities; consider cap_drop: [ALL] with explicit cap_add",
			Line:        svc.CapDropLine,
		})
	}

	if !svc.Privileged && !prof.HasSeccomp && !hasNoNewPrivileges(svc.SecurityOpt) {
		findings = append(findings, Finding{
			Service:     svc.Name,
			Source:      path,
			Severity:    SevMedium,
			Category:    "no_seccomp",
			Description: "no seccomp profile configured; container uses default Docker profile",
			Line:        svc.SecurityOptLine,
		})
	}

	return prof, findings
}

func analyzeKubeContainer(path string, kc collect.KubeContainer) (ServiceProfile, []Finding) {
	prof := ServiceProfile{
		Service:    kc.Name,
		Source:     path,
		Image:      kc.Image,
		Privileged: kc.Privileged,
		RunAsRoot:  kc.RunAsRoot,
	}

	var findings []Finding

	if kc.Privileged {
		findings = append(findings, Finding{
			Service:     kc.Name,
			Source:      path,
			Severity:    SevCritical,
			Category:    "privileged",
			Description: "Kubernetes container runs privileged, granting full host access",
			Line:        kc.PrivilegedLine,
		})
	}

	if kc.RunAsRoot {
		findings = append(findings, Finding{
			Service:     kc.Name,
			Source:      path,
			Severity:    SevHigh,
			Category:    "run_as_root",
			Description: "container explicitly runs as root (runAsUser: 0 or runAsNonRoot: false)",
			Line:        kc.RunAsRootLine,
		})
	}

	return prof, findings
}

func hasSeccomp(opts []string) bool {
	for _, o := range opts {
		if strings.Contains(strings.ToLower(o), "seccomp") {
			return true
		}
	}
	return false
}

func hasNoNewPrivileges(opts []string) bool {
	for _, o := range opts {
		if strings.EqualFold(strings.TrimSpace(o), "no-new-privileges:true") ||
			strings.EqualFold(strings.TrimSpace(o), "no-new-privileges") {
			return true
		}
	}
	return false
}

func hasDropAll(caps []string) bool {
	for _, c := range caps {
		if strings.EqualFold(c, "ALL") {
			return true
		}
	}
	return false
}

func filterDangerous(caps []string) []string {
	var out []string
	for _, c := range caps {
		upper := strings.ToUpper(strings.TrimSpace(c))
		if _, ok := dangerousCaps[upper]; ok {
			out = append(out, upper)
		}
	}
	sort.Strings(out)
	return out
}

func worstSeverity(caps []string) Severity {
	worst := SevInfo
	for _, c := range caps {
		if s, ok := dangerousCaps[strings.ToUpper(c)]; ok {
			if sevRank(s) < sevRank(worst) {
				worst = s
			}
		}
	}
	return worst
}

func sevRank(s Severity) int {
	switch s {
	case SevCritical:
		return 0
	case SevHigh:
		return 1
	case SevMedium:
		return 2
	case SevLow:
		return 3
	case SevInfo:
		return 4
	default:
		return 5
	}
}

func summarize(profiles []ServiceProfile, findings []Finding) Summary {
	s := Summary{
		TotalServices: len(profiles),
		BySeverity:    map[string]int{},
	}
	for _, p := range profiles {
		if p.Privileged {
			s.PrivilegedCount++
		}
		if !p.HasSeccomp && !p.Privileged {
			s.NoSeccompCount++
		}
	}
	for _, f := range findings {
		s.BySeverity[string(f.Severity)]++
		if f.Category == "dangerous_capability" {
			s.DangerousCapCount++
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Container Capability Analysis\n")
	b.WriteString("══════════════════════════════════════════════════════════════\n\n")

	b.WriteString(fmt.Sprintf("  Services analyzed: %d\n", r.Summary.TotalServices))
	b.WriteString(fmt.Sprintf("  Privileged:        %d\n", r.Summary.PrivilegedCount))
	b.WriteString(fmt.Sprintf("  No seccomp:        %d\n", r.Summary.NoSeccompCount))
	b.WriteString(fmt.Sprintf("  Dangerous caps:    %d\n", r.Summary.DangerousCapCount))
	b.WriteString(fmt.Sprintf("  Findings:          %d\n\n", len(r.Findings)))

	if len(r.Profiles) > 0 {
		b.WriteString(fmt.Sprintf("  %-20s %-30s %-6s %-8s %-10s\n",
			"Service", "Image", "Priv", "Seccomp", "Caps Added"))
		b.WriteString("  ────────────────────────────────────────────────────────────────────────────\n")
		for _, p := range r.Profiles {
			capsStr := "-"
			if len(p.CapAdd) > 0 {
				capsStr = strings.Join(p.CapAdd, ",")
			}
			seccomp := "no"
			if p.HasSeccomp {
				seccomp = "yes"
			}
			priv := "no"
			if p.Privileged {
				priv = "YES"
			}
			b.WriteString(fmt.Sprintf("  %-20s %-30s %-6s %-8s %-10s\n",
				truncate(p.Service, 20), truncate(p.Image, 30), priv, seccomp, truncate(capsStr, 10)))
		}
		b.WriteByte('\n')
	}

	if len(r.Findings) > 0 {
		b.WriteString("  Findings:\n")
		b.WriteString("  ────────────────────────────────────────────────────────────────────────────\n")
		for _, f := range r.Findings {
			line := ""
			if f.Line > 0 {
				line = fmt.Sprintf(" (line %d)", f.Line)
			}
			b.WriteString(fmt.Sprintf("  [%s] %s: %s%s\n",
				strings.ToUpper(string(f.Severity)), f.Service, f.Description, line))
		}
		b.WriteByte('\n')
	}

	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
