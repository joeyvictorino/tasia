package cronjob

import (
	"fmt"
	"regexp"
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
	TotalServices      int `json:"total_services"`
	TotalFindings      int `json:"total_findings"`
	CronAsRoot         int `json:"cron_as_root"`
	CronInEntrypoint   int `json:"cron_in_entrypoint"`
	CrontabMount       int `json:"crontab_mount"`
	CronPrivileged     int `json:"cron_privileged"`
	CronNoUser         int `json:"cron_no_user"`
	SchedulerEnvLeak   int `json:"scheduler_env_leak"`
}

var (
	cronCmdRe    = regexp.MustCompile(`(?i)\bcron(d|tab)?\b`)
	schedulerRe  = regexp.MustCompile(`(?i)\b(cron|schedule|periodic|at\s+job|timer)\b`)
	cronEnvKeyRe = regexp.MustCompile(`(?i)(CRON|SCHEDULE|PERIODIC|TIMER)`)
)

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

	hasCronCmd := false
	for _, part := range svc.Command {
		if cronCmdRe.MatchString(part) {
			hasCronCmd = true
			break
		}
	}
	if !hasCronCmd {
		for _, part := range svc.Entrypoint {
			if cronCmdRe.MatchString(part) {
				hasCronCmd = true
				break
			}
		}
	}

	if hasCronCmd && (svc.User == "" || svc.User == "root" || svc.User == "0") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "cronjob_as_root",
			Message: fmt.Sprintf("Service '%s' runs cron as root; scheduled tasks inherit root privileges", svc.Name),
		})
	}

	if hasCronCmd && svc.User == "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cronjob_no_user",
			Message: fmt.Sprintf("Service '%s' runs cron without explicit USER directive; defaults to root", svc.Name),
		})
	}

	if hasCronCmd && svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "cronjob_privileged",
			Message: fmt.Sprintf("Service '%s' runs cron in privileged mode; scheduled tasks have full host access", svc.Name),
		})
	}

	for _, ep := range svc.Entrypoint {
		if cronCmdRe.MatchString(ep) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "cronjob_in_entrypoint",
				Message: fmt.Sprintf("Service '%s' starts cron from entrypoint; consider a dedicated scheduler sidecar", svc.Name),
			})
			break
		}
	}

	for _, v := range svc.Volumes {
		lower := strings.ToLower(v)
		if strings.Contains(lower, "crontab") || strings.Contains(lower, "/cron.d") || strings.Contains(lower, "/etc/cron") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "cronjob_crontab_mount",
				Message: fmt.Sprintf("Service '%s' mounts crontab or cron directory from host: %s", svc.Name, v),
			})
		}
	}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 && cronEnvKeyRe.MatchString(parts[0]) {
			val := parts[1]
			if val != "" && !strings.HasPrefix(val, "${") && !strings.HasPrefix(val, "$") {
				if strings.ContainsAny(val, ";|&") || strings.Contains(val, "$(") {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "high",
						Rule:    "cronjob_scheduler_env_leak",
						Message: fmt.Sprintf("Service '%s' has scheduler env var '%s' containing shell metacharacters", svc.Name, parts[0]),
					})
				}
			}
		}
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "cronjob_as_root":
				s.CronAsRoot++
			case "cronjob_in_entrypoint":
				s.CronInEntrypoint++
			case "cronjob_crontab_mount":
				s.CrontabMount++
			case "cronjob_privileged":
				s.CronPrivileged++
			case "cronjob_no_user":
				s.CronNoUser++
			case "cronjob_scheduler_env_leak":
				s.SchedulerEnvLeak++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Cron/Scheduler Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Cron as root:          %d\n", r.Summary.CronAsRoot)
	fmt.Fprintf(&b, "  Cron in entrypoint:    %d\n", r.Summary.CronInEntrypoint)
	fmt.Fprintf(&b, "  Crontab mount:         %d\n", r.Summary.CrontabMount)
	fmt.Fprintf(&b, "  Cron privileged:       %d\n", r.Summary.CronPrivileged)
	fmt.Fprintf(&b, "  Cron no user:          %d\n", r.Summary.CronNoUser)
	fmt.Fprintf(&b, "  Scheduler env leak:    %d\n\n", r.Summary.SchedulerEnvLeak)
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
