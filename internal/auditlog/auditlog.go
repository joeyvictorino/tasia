package auditlog

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
	TotalServices         int `json:"total_services"`
	TotalFindings         int `json:"total_findings"`
	MissingLogConfig      int `json:"missing_log_config"`
	UnboundedLogging      int `json:"unbounded_logging"`
	InsecureLogPaths      int `json:"insecure_log_paths"`
	MissingLogRedirection int `json:"missing_log_redirection"`
}

var insecureLogPaths = []string{
	"/dev/null", "/tmp", "/var/tmp",
	"/dev/shm",
}

func logDriver(svc compose.Service) string {
	if svc.Logging != nil && svc.Logging.Driver != "" {
		return strings.ToLower(svc.Logging.Driver)
	}
	return ""
}

func logOpts(svc compose.Service) map[string]string {
	if svc.Logging != nil {
		return svc.Logging.Options
	}
	return nil
}

func hasLogDriver(svc compose.Service) bool {
	if svc.Logging != nil && svc.Logging.Driver != "" {
		return true
	}
	for _, env := range svc.Environment {
		upper := strings.ToUpper(env)
		if strings.HasPrefix(upper, "LOG_DRIVER=") || strings.HasPrefix(upper, "LOGGING_DRIVER=") {
			return true
		}
	}
	return false
}

func isInsecureLogPath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	for _, p := range insecureLogPaths {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

func hasLogMaxSize(svc compose.Service) bool {
	opts := logOpts(svc)
	for k, v := range opts {
		if strings.ToLower(k) == "max-size" && v != "" {
			return true
		}
	}
	return false
}

func hasLogMaxFile(svc compose.Service) bool {
	opts := logOpts(svc)
	for k, v := range opts {
		if strings.ToLower(k) == "max-file" && v != "" {
			return true
		}
	}
	return false
}

func logVolumeTargets(svc compose.Service) []string {
	var targets []string
	for _, v := range svc.Volumes {
		parts := strings.Split(v, ":")
		if len(parts) < 2 {
			continue
		}
		cp := parts[1]
		if strings.Contains(strings.ToLower(cp), "log") ||
			strings.HasSuffix(strings.ToLower(cp), "/logs") ||
			strings.HasPrefix(cp, "/var/log") {
			targets = append(targets, v)
		}
	}
	return targets
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	driver := logDriver(svc)

	if driver == "none" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "logging_disabled",
			Message: fmt.Sprintf("Service '%s' has logging disabled (driver: none); agent actions are not auditable", svc.Name),
		})
	}

	if driver == "json-file" || driver == "" {
		if !hasLogMaxSize(svc) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "unbounded_log_size",
				Message: fmt.Sprintf("Service '%s' uses %s logging without max-size limit; logs can grow unbounded and fill disk", svc.Name, driverName(driver)),
			})
		}
		if !hasLogMaxFile(svc) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "missing_log_rotation",
				Message: fmt.Sprintf("Service '%s' uses %s logging without max-file limit; old log files are never rotated out", svc.Name, driverName(driver)),
			})
		}
	}

	for _, v := range svc.Volumes {
		parts := strings.Split(v, ":")
		if len(parts) < 2 {
			continue
		}
		cp := parts[1]
		if isInsecureLogPath(cp) {
			isLog := strings.Contains(strings.ToLower(parts[0]), "log")
			if isLog {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "insecure_log_path",
					Message: fmt.Sprintf("Service '%s' directs logs to insecure path '%s'; logs could be lost or tampered with", svc.Name, cp),
				})
			}
		}
	}

	logVolumes := logVolumeTargets(svc)
	for _, lv := range logVolumes {
		parts := strings.Split(lv, ":")
		if len(parts) >= 2 {
			writable := true
			if len(parts) >= 3 && strings.Contains(strings.ToLower(parts[2]), "ro") {
				writable = false
			}
			if !writable {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "readonly_log_mount",
					Message: fmt.Sprintf("Service '%s' has log directory '%s' mounted read-only; logging will fail silently", svc.Name, parts[1]),
				})
			}
		}
	}

	hasStdout := false
	for _, env := range svc.Environment {
		lower := strings.ToLower(env)
		if strings.Contains(lower, "log_to_stdout") || strings.Contains(lower, "log_output=stdout") {
			hasStdout = true
		}
	}
	if !hasStdout && !hasLogDriver(svc) && len(logVolumes) == 0 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "no_log_configuration",
			Message: fmt.Sprintf("Service '%s' has no explicit log configuration; default logging may miss agent activity", svc.Name),
		})
	}

	return sr
}

func driverName(driver string) string {
	if driver == "" {
		return "default (json-file)"
	}
	return driver
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

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "no_log_configuration", "logging_disabled":
				s.MissingLogConfig++
			case "unbounded_log_size", "missing_log_rotation":
				s.UnboundedLogging++
			case "insecure_log_path":
				s.InsecureLogPaths++
			case "readonly_log_mount":
				s.MissingLogRedirection++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Audit Log Configuration Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Missing log config:       %d\n", r.Summary.MissingLogConfig)
	fmt.Fprintf(&b, "  Unbounded logging:        %d\n", r.Summary.UnboundedLogging)
	fmt.Fprintf(&b, "  Insecure log paths:       %d\n", r.Summary.InsecureLogPaths)
	fmt.Fprintf(&b, "  Missing log redirection:  %d\n\n", r.Summary.MissingLogRedirection)
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
