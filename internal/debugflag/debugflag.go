package debugflag

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
	TotalServices    int `json:"total_services"`
	TotalFindings    int `json:"total_findings"`
	DebugPorts       int `json:"debug_ports"`
	DebugEnvVars     int `json:"debug_env_vars"`
	VerboseLogging   int `json:"verbose_logging"`
	DebugEntrypoints int `json:"debug_entrypoints"`
	DevMode          int `json:"dev_mode"`
	DebugPrivileged  int `json:"debug_privileged"`
}

var debugPorts = map[string]bool{
	"5005": true, "5858": true, "9229": true, "9222": true,
	"4000": true, "2345": true, "8787": true, "1234": true,
}

var debugEnvKeys = []string{
	"DEBUG", "NODE_DEBUG", "FLASK_DEBUG", "DJANGO_DEBUG",
	"VERBOSE", "LOG_LEVEL", "RUST_LOG", "PYTHONDONTWRITEBYTECODE",
}

var debugEnvValues = []string{
	"debug", "trace", "verbose", "true", "1", "yes",
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

	for _, p := range svc.Ports {
		hp := fmt.Sprintf("%d", p.TargetPort)
		if debugPorts[hp] {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "debug_port_exposed",
				Message: fmt.Sprintf("Service '%s' exposes debug port %s; remote debugger access in production is dangerous", svc.Name, hp),
			})
		}
	}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToUpper(parts[0])
		val := strings.ToLower(parts[1])

		for _, dk := range debugEnvKeys {
			if strings.Contains(key, dk) {
				for _, dv := range debugEnvValues {
					if val == dv {
						sr.Findings = append(sr.Findings, Finding{
							Level:   "medium",
							Rule:    "debug_env_enabled",
							Message: fmt.Sprintf("Service '%s' has debug environment variable %s=%s; debug mode leaks internal state", svc.Name, parts[0], parts[1]),
						})
						break
					}
				}
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
		if (key == "LOG_LEVEL" || key == "LOGLEVEL" || key == "LOGGING_LEVEL") && (val == "trace" || val == "debug") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "debug_verbose_logging",
				Message: fmt.Sprintf("Service '%s' has verbose logging (%s=%s); may expose sensitive data in logs", svc.Name, parts[0], parts[1]),
			})
			break
		}
	}

	if len(svc.Entrypoint) > 0 {
		ep := strings.ToLower(strings.Join(svc.Entrypoint, " "))
		if strings.Contains(ep, "--debug") || strings.Contains(ep, "--inspect") || strings.Contains(ep, "-agentlib:jdwp") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "debug_entrypoint",
				Message: fmt.Sprintf("Service '%s' entrypoint contains debug flags; debugger is active in production", svc.Name),
			})
		}
	}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToUpper(parts[0])
		val := strings.ToLower(parts[1])
		if (strings.Contains(key, "ENV") || strings.Contains(key, "MODE") || strings.Contains(key, "STAGE")) &&
			(val == "development" || val == "dev" || val == "staging") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "debug_dev_mode",
				Message: fmt.Sprintf("Service '%s' is in development mode (%s=%s); non-production configuration may be insecure", svc.Name, parts[0], parts[1]),
			})
			break
		}
	}

	if svc.Privileged {
		hasDebug := false
		for _, f := range sr.Findings {
			if f.Rule == "debug_port_exposed" || f.Rule == "debug_env_enabled" || f.Rule == "debug_entrypoint" {
				hasDebug = true
				break
			}
		}
		if hasDebug {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "debug_privileged",
				Message: fmt.Sprintf("Service '%s' is privileged with debug features enabled; full host access plus debugger is a direct compromise vector", svc.Name),
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
			case "debug_port_exposed":
				s.DebugPorts++
			case "debug_env_enabled":
				s.DebugEnvVars++
			case "debug_verbose_logging":
				s.VerboseLogging++
			case "debug_entrypoint":
				s.DebugEntrypoints++
			case "debug_dev_mode":
				s.DevMode++
			case "debug_privileged":
				s.DebugPrivileged++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Debug Flag Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Debug ports exposed:   %d\n", r.Summary.DebugPorts)
	fmt.Fprintf(&b, "  Debug env vars:        %d\n", r.Summary.DebugEnvVars)
	fmt.Fprintf(&b, "  Verbose logging:       %d\n", r.Summary.VerboseLogging)
	fmt.Fprintf(&b, "  Debug entrypoints:     %d\n", r.Summary.DebugEntrypoints)
	fmt.Fprintf(&b, "  Dev mode enabled:      %d\n", r.Summary.DevMode)
	fmt.Fprintf(&b, "  Debug + privileged:    %d\n\n", r.Summary.DebugPrivileged)
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
