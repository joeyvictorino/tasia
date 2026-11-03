package timesync

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
	TotalServices      int `json:"total_services"`
	TotalFindings      int `json:"total_findings"`
	NoTimezone         int `json:"no_timezone"`
	MixedTimezones     int `json:"mixed_timezones"`
	UtcNotEnforced     int `json:"utc_not_enforced"`
	NtpDisabled        int `json:"ntp_disabled"`
	HostTimeMounted    int `json:"host_time_mounted"`
	PrivilegedTimeDrift int `json:"privileged_time_drift"`
}

var nonUtcTimezones = []string{
	"us/eastern", "us/pacific", "us/central", "america/",
	"europe/", "asia/", "australia/", "pacific/", "africa/",
	"est", "pst", "cst", "mst",
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

	hasTZ := false
	tzValue := ""
	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 && strings.ToUpper(parts[0]) == "TZ" {
			hasTZ = true
			tzValue = strings.ToLower(parts[1])
			break
		}
	}

	if !hasTZ {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "time_no_timezone",
			Message: fmt.Sprintf("Service '%s' has no TZ environment variable; timezone defaults to container image setting which may differ across services", svc.Name),
		})
	}

	if hasTZ && tzValue != "utc" && tzValue != "etc/utc" && tzValue != "gmt" {
		for _, ntz := range nonUtcTimezones {
			if strings.Contains(tzValue, ntz) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "time_utc_not_enforced",
					Message: fmt.Sprintf("Service '%s' uses non-UTC timezone TZ=%s; local timezones cause log correlation issues and scheduling bugs", svc.Name, tzValue),
				})
				break
			}
		}
	}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToUpper(parts[0])
		val := strings.ToLower(parts[1])
		if (key == "NTP_ENABLED" || key == "ENABLE_NTP" || key == "USE_NTP") && (val == "false" || val == "0" || val == "no") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "time_ntp_disabled",
				Message: fmt.Sprintf("Service '%s' has NTP explicitly disabled (%s=%s); clock drift will cause auth failures and log inconsistencies", svc.Name, parts[0], parts[1]),
			})
			break
		}
	}

	for _, v := range svc.Volumes {
		vol := strings.ToLower(v)
		if strings.Contains(vol, "/etc/localtime") || strings.Contains(vol, "/etc/timezone") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "time_host_mounted",
				Message: fmt.Sprintf("Service '%s' mounts host time file (%s); container timezone depends on host and breaks portability", svc.Name, v),
			})
			break
		}
	}

	if svc.Privileged {
		hasTimeIssue := false
		for _, f := range sr.Findings {
			if f.Rule == "time_ntp_disabled" || f.Rule == "time_no_timezone" {
				hasTimeIssue = true
				break
			}
		}
		if hasTimeIssue {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "time_privileged_drift",
				Message: fmt.Sprintf("Service '%s' is privileged with time configuration issues; a privileged container can modify host system clock", svc.Name),
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
			case "time_no_timezone":
				s.NoTimezone++
			case "time_mixed_timezones":
				s.MixedTimezones++
			case "time_utc_not_enforced":
				s.UtcNotEnforced++
			case "time_ntp_disabled":
				s.NtpDisabled++
			case "time_host_mounted":
				s.HostTimeMounted++
			case "time_privileged_drift":
				s.PrivilegedTimeDrift++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Time Sync Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No timezone set:       %d\n", r.Summary.NoTimezone)
	fmt.Fprintf(&b, "  Mixed timezones:       %d\n", r.Summary.MixedTimezones)
	fmt.Fprintf(&b, "  UTC not enforced:      %d\n", r.Summary.UtcNotEnforced)
	fmt.Fprintf(&b, "  NTP disabled:          %d\n", r.Summary.NtpDisabled)
	fmt.Fprintf(&b, "  Host time mounted:     %d\n", r.Summary.HostTimeMounted)
	fmt.Fprintf(&b, "  Privileged time drift: %d\n\n", r.Summary.PrivilegedTimeDrift)
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
