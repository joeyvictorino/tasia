package loginjection

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
	UnsafeLogDrivers    int `json:"unsafe_log_drivers"`
	MissingLogLimits    int `json:"missing_log_limits"`
	LogMountExposed     int `json:"log_mount_exposed"`
	EnvInLogPath        int `json:"env_in_log_path"`
	ExternalLogUnsecure int `json:"external_log_unsecure"`
	DebugLogEnabled     int `json:"debug_log_enabled"`
}

var riskyLogDrivers = map[string]string{
	"syslog":    "syslog driver sends logs to host syslog; injection may pollute host audit trail",
	"journald":  "journald driver sends to host journal; crafted messages can inject false log entries",
	"gelf":      "gelf sends to Graylog; unsecured transport allows log injection in transit",
	"fluentd":   "fluentd driver forwards logs; misconfigured parsers can be exploited for injection",
}

var debugEnvPatterns = []string{
	"DEBUG=TRUE", "DEBUG=1", "DEBUG=YES",
	"LOG_LEVEL=DEBUG", "LOG_LEVEL=TRACE",
	"LOGLEVEL=DEBUG", "LOGLEVEL=TRACE",
	"RUST_LOG=DEBUG", "RUST_LOG=TRACE",
	"VERBOSE=TRUE", "VERBOSE=1",
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

	if svc.Logging != nil {
		driver := strings.ToLower(svc.Logging.Driver)
		if desc, ok := riskyLogDrivers[driver]; ok {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "unsafe_log_driver",
				Message: fmt.Sprintf("Service '%s' uses log driver '%s'; %s", svc.Name, driver, desc),
			})
		}

		hasMaxSize := false
		hasMaxFile := false
		for k := range svc.Logging.Options {
			if k == "max-size" {
				hasMaxSize = true
			}
			if k == "max-file" {
				hasMaxFile = true
			}
		}
		if driver == "json-file" || driver == "" {
			if !hasMaxSize {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "missing_log_size_limit",
					Message: fmt.Sprintf("Service '%s' uses json-file log driver without max-size; logs can grow unbounded", svc.Name),
				})
			}
			if !hasMaxFile {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "low",
					Rule:    "missing_log_file_limit",
					Message: fmt.Sprintf("Service '%s' uses json-file log driver without max-file; log rotation not configured", svc.Name),
				})
			}
		}
	} else {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "no_logging_config",
			Message: fmt.Sprintf("Service '%s' has no explicit logging configuration; using default driver without limits", svc.Name),
		})
	}

	for _, vol := range svc.Volumes {
		parts := strings.SplitN(vol, ":", 2)
		if len(parts) >= 2 {
			src := strings.ToLower(parts[0])
			dst := strings.ToLower(parts[1])
			if strings.Contains(src, "/var/log") || strings.Contains(dst, "/var/log") {
				isRO := strings.Contains(vol, ":ro")
				if !isRO {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "high",
						Rule:    "log_mount_writable",
						Message: fmt.Sprintf("Service '%s' mounts log directory writable; container can inject entries into host logs", svc.Name),
					})
				}
			}
		}
	}

	for _, env := range svc.Environment {
		envUpper := strings.ToUpper(env)
		for _, pattern := range debugEnvPatterns {
			if strings.Contains(envUpper, pattern) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "debug_logging_enabled",
					Message: fmt.Sprintf("Service '%s' has debug logging enabled (%s); verbose logs may expose sensitive data", svc.Name, strings.SplitN(env, "=", 2)[0]),
				})
				break
			}
		}

		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			key := strings.ToUpper(parts[0])
			val := parts[1]
			if strings.Contains(key, "LOG") && strings.Contains(key, "PATH") {
				if strings.Contains(val, "..") || strings.HasPrefix(val, "/") {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "high",
						Rule:    "log_path_traversal",
						Message: fmt.Sprintf("Service '%s' sets log path via env var %s=%s; path traversal risk", svc.Name, parts[0], val),
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
		s.TotalFindings += len(sr.Findings)
		for _, f := range sr.Findings {
			switch f.Rule {
			case "unsafe_log_driver":
				s.UnsafeLogDrivers++
			case "missing_log_size_limit", "missing_log_file_limit", "no_logging_config":
				s.MissingLogLimits++
			case "log_mount_writable":
				s.LogMountExposed++
			case "log_path_traversal":
				s.EnvInLogPath++
			case "debug_logging_enabled":
				s.DebugLogEnabled++
			}
		}
	}
	return s
}
