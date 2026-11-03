package cronaudit

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
	RootCronJobs        int `json:"root_cron_jobs"`
	WritableCrontabs    int `json:"writable_crontabs"`
	MissingCronLogging  int `json:"missing_cron_logging"`
	PrivilegedScheduled int `json:"privileged_scheduled"`
	CronInContainers    int `json:"cron_in_containers"`
}

var cronImages = []string{
	"cron", "supercronic", "crond", "ofelia", "mcuadros/ofelia",
	"aptible/supercronic", "willfarrell/crontab",
}

var cronEnvPatterns = []string{
	"CRON_SCHEDULE=",
	"CRONTAB=",
	"CRON_JOB=",
	"CRON_CMD=",
	"CRON_EXPRESSION=",
	"SCHEDULE=",
}

func isCronImage(image string) bool {
	lower := strings.ToLower(image)
	for _, ci := range cronImages {
		if strings.Contains(lower, ci) {
			return true
		}
	}
	return false
}

func hasCronEnv(envVars []string) (string, string) {
	for _, e := range envVars {
		upper := strings.ToUpper(e)
		for _, pat := range cronEnvPatterns {
			if strings.HasPrefix(upper, pat) {
				parts := strings.SplitN(e, "=", 2)
				if len(parts) == 2 {
					return parts[0], parts[1]
				}
			}
		}
	}
	return "", ""
}

func hasCrontabMount(volumes []string) (string, bool) {
	for _, v := range volumes {
		lower := strings.ToLower(v)
		if strings.Contains(lower, "crontab") || strings.Contains(lower, "/etc/cron") || strings.Contains(lower, "/var/spool/cron") {
			return v, true
		}
	}
	return "", false
}

func isWritableMount(vol string) bool {
	parts := strings.Split(vol, ":")
	if len(parts) < 2 {
		return true
	}
	if len(parts) >= 3 {
		opts := strings.ToLower(parts[2])
		return !strings.Contains(opts, "ro")
	}
	return true
}

func hasCronLogging(envVars []string) bool {
	for _, e := range envVars {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "CRON_LOG") || strings.Contains(upper, "LOG_CRON") || strings.Contains(upper, "CRON_OUTPUT") {
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

	hasCron := isCronImage(svc.Image)
	cronKey, _ := hasCronEnv(svc.Environment)
	cronMount, hasMnt := hasCrontabMount(svc.Volumes)

	if hasCron {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cronaudit_cron_in_container",
			Message: fmt.Sprintf("Service '%s' runs a cron scheduler (image: %s); cron inside containers lacks audit trails and process isolation", svc.Name, svc.Image),
		})
	}

	if cronKey != "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cronaudit_cron_in_container",
			Message: fmt.Sprintf("Service '%s' has cron schedule via environment variable '%s'; scheduled tasks in containers are harder to audit", svc.Name, cronKey),
		})
	}

	if hasMnt {
		if isWritableMount(cronMount) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "cronaudit_writable_crontab",
				Message: fmt.Sprintf("Service '%s' mounts crontab path writable (%s); an attacker could inject scheduled commands", svc.Name, cronMount),
			})
		} else {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "cronaudit_crontab_mount",
				Message: fmt.Sprintf("Service '%s' mounts crontab path read-only (%s); verify cron entries are reviewed", svc.Name, cronMount),
			})
		}
	}

	if (hasCron || cronKey != "") && svc.Privileged {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "cronaudit_privileged_cron",
			Message: fmt.Sprintf("Service '%s' runs cron jobs in a privileged container; scheduled tasks have unrestricted host access", svc.Name),
		})
	}

	if (hasCron || cronKey != "") && !hasCronLogging(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cronaudit_no_logging",
			Message: fmt.Sprintf("Service '%s' runs cron jobs without explicit log configuration; cron output may be silently lost", svc.Name),
		})
	}

	for _, e := range svc.Environment {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		val := parts[1]
		if strings.Contains(strings.ToUpper(parts[0]), "CRON") && (strings.Contains(val, "root") || strings.Contains(val, "sudo")) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "cronaudit_root_cron",
				Message: fmt.Sprintf("Service '%s' configures cron to run as root/sudo via '%s'; use a non-root user for scheduled tasks", svc.Name, parts[0]),
			})
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
			case "cronaudit_root_cron":
				s.RootCronJobs++
			case "cronaudit_writable_crontab":
				s.WritableCrontabs++
			case "cronaudit_no_logging":
				s.MissingCronLogging++
			case "cronaudit_privileged_cron":
				s.PrivilegedScheduled++
			case "cronaudit_cron_in_container":
				s.CronInContainers++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Cron Job Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Root cron jobs:          %d\n", r.Summary.RootCronJobs)
	fmt.Fprintf(&b, "  Writable crontabs:       %d\n", r.Summary.WritableCrontabs)
	fmt.Fprintf(&b, "  Missing cron logging:    %d\n", r.Summary.MissingCronLogging)
	fmt.Fprintf(&b, "  Privileged scheduled:    %d\n", r.Summary.PrivilegedScheduled)
	fmt.Fprintf(&b, "  Cron in containers:      %d\n\n", r.Summary.CronInContainers)
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
