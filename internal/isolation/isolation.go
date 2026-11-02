package isolation

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type ServiceScore struct {
	Service   string           `json:"service"`
	File      string           `json:"file"`
	Score     int              `json:"score"`
	Grade     string           `json:"grade"`
	Breakdown map[string]Check `json:"breakdown"`
}

type Check struct {
	Passed      bool   `json:"passed"`
	Points      int    `json:"points"`
	Description string `json:"description"`
}

type Report struct {
	Path     string         `json:"path"`
	Services []ServiceScore `json:"services"`
	Summary  Summary        `json:"summary"`
}

type Summary struct {
	TotalServices int     `json:"total_services"`
	AverageScore  float64 `json:"average_score"`
	MinScore      int     `json:"min_score"`
	MaxScore      int     `json:"max_score"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			ss := scoreService(svc, cf.Path)
			r.Services = append(r.Services, ss)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func scoreService(svc compose.Service, file string) ServiceScore {
	ss := ServiceScore{
		Service:   svc.Name,
		File:      file,
		Breakdown: make(map[string]Check),
	}

	total := 0
	earned := 0

	// Not privileged (20 points)
	total += 20
	notPriv := !svc.Privileged
	if notPriv {
		earned += 20
	}
	ss.Breakdown["not_privileged"] = Check{
		Passed:      notPriv,
		Points:      20,
		Description: "Container not running in privileged mode",
	}

	// Drops ALL capabilities (15 points)
	total += 15
	dropsAll := hasCapDrop(svc.CapDrop, "ALL")
	if dropsAll {
		earned += 15
	}
	ss.Breakdown["cap_drop_all"] = Check{
		Passed:      dropsAll,
		Points:      15,
		Description: "Drops ALL capabilities before adding specific ones",
	}

	// No dangerous capabilities added (15 points)
	total += 15
	noDanger := !hasDangerousCaps(svc.CapAdd)
	if noDanger {
		earned += 15
	}
	ss.Breakdown["no_dangerous_caps"] = Check{
		Passed:      noDanger,
		Points:      15,
		Description: "No dangerous capabilities added (SYS_ADMIN, SYS_PTRACE, NET_ADMIN, SYS_MODULE)",
	}

	// Not using host network (10 points)
	total += 10
	noHostNet := svc.NetworkMode != "host"
	if noHostNet {
		earned += 10
	}
	ss.Breakdown["no_host_network"] = Check{
		Passed:      noHostNet,
		Points:      10,
		Description: "Not using host network namespace",
	}

	// Has seccomp profile (10 points)
	total += 10
	hasSeccomp := hasSecurityOptPrefix(svc.SecurityOpt, "seccomp")
	if hasSeccomp {
		earned += 10
	}
	ss.Breakdown["seccomp_profile"] = Check{
		Passed:      hasSeccomp,
		Points:      10,
		Description: "Seccomp security profile configured",
	}

	// Has apparmor profile (10 points)
	total += 10
	hasApparmor := hasSecurityOptPrefix(svc.SecurityOpt, "apparmor")
	if hasApparmor {
		earned += 10
	}
	ss.Breakdown["apparmor_profile"] = Check{
		Passed:      hasApparmor,
		Points:      10,
		Description: "AppArmor security profile configured",
	}

	// No sensitive host mounts (10 points)
	total += 10
	noSensitive := !hasSensitiveMount(svc.Volumes)
	if noSensitive {
		earned += 10
	}
	ss.Breakdown["no_sensitive_mounts"] = Check{
		Passed:      noSensitive,
		Points:      10,
		Description: "No sensitive host paths mounted (/var/run/docker.sock, /proc, /sys)",
	}

	// No no-new-privileges disabled (10 points)
	total += 10
	hasNoNewPrivs := hasSecurityOptValue(svc.SecurityOpt, "no-new-privileges:true") ||
		hasSecurityOptValue(svc.SecurityOpt, "no-new-privileges=true")
	if hasNoNewPrivs {
		earned += 10
	}
	ss.Breakdown["no_new_privileges"] = Check{
		Passed:      hasNoNewPrivs,
		Points:      10,
		Description: "no-new-privileges flag set to prevent privilege escalation",
	}

	if total > 0 {
		ss.Score = (earned * 100) / total
	}
	ss.Grade = gradeFromScore(ss.Score)
	return ss
}

func gradeFromScore(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func hasCapDrop(caps []string, target string) bool {
	for _, c := range caps {
		if strings.EqualFold(c, target) {
			return true
		}
	}
	return false
}

var dangerousCaps = map[string]bool{
	"SYS_ADMIN":  true,
	"SYS_PTRACE": true,
	"NET_ADMIN":  true,
	"SYS_MODULE": true,
	"SYS_RAWIO":  true,
	"ALL":        true,
}

func hasDangerousCaps(caps []string) bool {
	for _, c := range caps {
		if dangerousCaps[strings.ToUpper(c)] {
			return true
		}
	}
	return false
}

func hasSecurityOptPrefix(opts []string, prefix string) bool {
	for _, o := range opts {
		if strings.HasPrefix(strings.ToLower(o), prefix) {
			return true
		}
	}
	return false
}

func hasSecurityOptValue(opts []string, value string) bool {
	for _, o := range opts {
		if strings.EqualFold(o, value) {
			return true
		}
	}
	return false
}

var sensitivePaths = []string{
	"/var/run/docker.sock",
	"/proc",
	"/sys",
	"/dev",
	"/etc/shadow",
	"/etc/passwd",
}

func hasSensitiveMount(vols []string) bool {
	for _, v := range vols {
		src := strings.SplitN(v, ":", 2)[0]
		for _, sp := range sensitivePaths {
			if src == sp || strings.HasPrefix(src, sp+"/") {
				return true
			}
		}
	}
	return false
}

func summarize(services []ServiceScore) Summary {
	s := Summary{TotalServices: len(services)}
	if len(services) == 0 {
		return s
	}
	total := 0
	s.MinScore = 101
	s.MaxScore = -1
	for _, svc := range services {
		total += svc.Score
		if svc.Score < s.MinScore {
			s.MinScore = svc.Score
		}
		if svc.Score > s.MaxScore {
			s.MaxScore = svc.Score
		}
	}
	s.AverageScore = float64(total) / float64(len(services))
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Container Isolation Audit (%d services, avg score %.0f/100)\n\n",
		r.Summary.TotalServices, r.Summary.AverageScore)
	for _, svc := range r.Services {
		fmt.Fprintf(&b, "  %-30s Score: %d/100 [%s]\n", svc.Service, svc.Score, svc.Grade)
		fmt.Fprintf(&b, "    file: %s\n", svc.File)
		for name, check := range svc.Breakdown {
			status := "PASS"
			if !check.Passed {
				status = "FAIL"
			}
			fmt.Fprintf(&b, "    [%s] %s (%d pts): %s\n", status, name, check.Points, check.Description)
		}
		b.WriteString("\n")
	}
	return b.String()
}
