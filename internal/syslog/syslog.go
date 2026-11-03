package syslog

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
	TotalServices        int `json:"total_services"`
	TotalFindings        int `json:"total_findings"`
	HostSyslogMounts     int `json:"host_syslog_mounts"`
	LogDriverMissing     int `json:"log_driver_missing"`
	VerboseLogging       int `json:"verbose_logging"`
	SyslogSocketExposed  int `json:"syslog_socket_exposed"`
}

var syslogPaths = []string{
	"/var/log/syslog", "/var/log/messages", "/var/log/auth.log",
	"/var/log/secure", "/var/log/kern.log", "/var/log/daemon.log",
	"/var/log/mail.log", "/var/log/cron", "/var/log",
}

var syslogSockets = []string{
	"/dev/log", "/var/run/syslog", "/run/systemd/journal/syslog",
	"/var/run/rsyslog", "/run/systemd/journal/dev-log",
}

var verboseEnvVars = []string{
	"LOG_LEVEL=DEBUG", "LOG_LEVEL=TRACE", "LOGLEVEL=DEBUG",
	"LOGLEVEL=TRACE", "DEBUG=TRUE", "DEBUG=1", "VERBOSE=TRUE",
	"VERBOSE=1", "RUST_LOG=TRACE", "RUST_LOG=DEBUG",
}

func isSyslogPath(path string) bool {
	lower := strings.ToLower(path)
	for _, sp := range syslogPaths {
		if strings.HasPrefix(lower, sp) {
			return true
		}
	}
	return false
}

func isSyslogSocket(path string) bool {
	for _, ss := range syslogSockets {
		if path == ss {
			return true
		}
	}
	return false
}

func isVerboseEnv(env string) bool {
	upper := strings.ToUpper(strings.TrimSpace(env))
	for _, ve := range verboseEnvVars {
		if upper == ve {
			return true
		}
	}
	return false
}

func extractVolumeSrc(vol string) string {
	parts := strings.SplitN(vol, ":", 2)
	if len(parts) >= 1 {
		return parts[0]
	}
	return vol
}

func extractVolumeDst(vol string) string {
	parts := strings.SplitN(vol, ":", 3)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
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

	for _, vol := range svc.Volumes {
		src := extractVolumeSrc(vol)
		dst := extractVolumeDst(vol)
		if isSyslogPath(src) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "host_syslog_mount",
				Message: fmt.Sprintf("Service '%s' mounts host syslog path '%s'; exposes system log data to container and may allow log tampering", svc.Name, src),
			})
		}
		if isSyslogSocket(src) || isSyslogSocket(dst) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "syslog_socket_exposed",
				Message: fmt.Sprintf("Service '%s' exposes syslog socket '%s'; container can inject arbitrary syslog messages into host logging", svc.Name, vol),
			})
		}
	}

	for _, env := range svc.Environment {
		if isVerboseEnv(env) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "verbose_logging",
				Message: fmt.Sprintf("Service '%s' has verbose logging enabled (%s); may expose sensitive data in logs in production", svc.Name, env),
			})
			break
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
			case "host_syslog_mount":
				s.HostSyslogMounts++
			case "log_driver_missing":
				s.LogDriverMissing++
			case "verbose_logging":
				s.VerboseLogging++
			case "syslog_socket_exposed":
				s.SyslogSocketExposed++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Syslog Configuration Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Host syslog mounts:    %d\n", r.Summary.HostSyslogMounts)
	fmt.Fprintf(&b, "  Syslog socket exposed: %d\n", r.Summary.SyslogSocketExposed)
	fmt.Fprintf(&b, "  Verbose logging:       %d\n\n", r.Summary.VerboseLogging)
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
