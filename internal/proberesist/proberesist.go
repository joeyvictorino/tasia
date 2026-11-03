package proberesist

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
	TotalServices     int `json:"total_services"`
	TotalFindings     int `json:"total_findings"`
	DebugEndpoints    int `json:"debug_endpoints"`
	VersionHeaders    int `json:"version_headers"`
	StackTraceLeaks   int `json:"stack_trace_leaks"`
	BannerExposures   int `json:"banner_exposures"`
	StatusEndpoints   int `json:"status_endpoints"`
}

var debugPorts = map[string]string{
	"5005":  "Java debug",
	"5858":  "Node.js legacy debug",
	"9229":  "Node.js inspector",
	"4200":  "Angular dev server",
	"3000":  "dev server",
	"8080":  "common debug/admin",
	"2345":  "Go delve debugger",
	"5678":  "Python debugpy",
	"9222":  "Chrome DevTools",
	"1234":  "generic debug",
	"6060":  "Go pprof",
	"15672": "RabbitMQ management",
	"8500":  "Consul UI",
	"2379":  "etcd client",
}

var debugEnvPatterns = []string{
	"DEBUG=TRUE", "DEBUG=1", "DEBUG=YES",
	"NODE_ENV=DEVELOPMENT",
	"FLASK_DEBUG=1", "FLASK_DEBUG=TRUE",
	"DJANGO_DEBUG=TRUE", "DJANGO_DEBUG=1",
	"RAILS_ENV=DEVELOPMENT",
	"APP_DEBUG=TRUE", "APP_DEBUG=1",
	"ENABLE_PROFILING=TRUE", "ENABLE_PROFILING=1",
	"PPROF_ENABLED=TRUE", "PPROF_ENABLED=1",
}

var versionEnvPatterns = []string{
	"SERVER_BANNER=",
	"X_POWERED_BY=",
	"SERVER_TOKENS=ON",
	"EXPOSE_VERSION=TRUE",
	"SHOW_VERSION=TRUE",
}

var stackTraceEnvPatterns = []string{
	"SHOW_ERRORS=TRUE", "SHOW_ERRORS=1",
	"DETAILED_ERRORS=TRUE", "DETAILED_ERRORS=1",
	"DISPLAY_ERRORS=1",
	"ERROR_REPORTING=E_ALL",
	"RUST_BACKTRACE=1", "RUST_BACKTRACE=FULL",
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

	for _, pm := range svc.Ports {
		pub := fmt.Sprintf("%d", pm.HostPort)
		if pm.HostPort == 0 {
			pub = fmt.Sprintf("%d", pm.TargetPort)
		}
		if desc, ok := debugPorts[pub]; ok {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "proberesist_debug_port",
				Message: fmt.Sprintf("Service '%s' exposes port %s (%s) which enables remote reconnaissance and debugging", svc.Name, pub, desc),
			})
		}
	}

	envUpper := make([]string, len(svc.Environment))
	for i, e := range svc.Environment {
		envUpper[i] = strings.ToUpper(e)
	}

	for _, pat := range debugEnvPatterns {
		for _, eu := range envUpper {
			if strings.Contains(eu, pat) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "proberesist_debug_enabled",
					Message: fmt.Sprintf("Service '%s' has debug mode enabled via '%s'; debug endpoints leak internal state to probes", svc.Name, strings.SplitN(eu, "=", 2)[0]),
				})
				break
			}
		}
	}

	for _, pat := range versionEnvPatterns {
		for i, eu := range envUpper {
			if strings.Contains(eu, pat) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "proberesist_version_header",
					Message: fmt.Sprintf("Service '%s' may expose version/server headers via '%s'; version info aids targeted attacks", svc.Name, strings.SplitN(svc.Environment[i], "=", 2)[0]),
				})
				break
			}
		}
	}

	for _, pat := range stackTraceEnvPatterns {
		for _, eu := range envUpper {
			if strings.Contains(eu, pat) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "critical",
					Rule:    "proberesist_stack_trace",
					Message: fmt.Sprintf("Service '%s' may leak stack traces via '%s'; stack traces reveal internal paths, library versions, and code structure", svc.Name, strings.SplitN(eu, "=", 2)[0]),
				})
				break
			}
		}
	}

	for _, e := range svc.Environment {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToUpper(parts[0])
		val := strings.ToLower(parts[1])
		if key == "STATUS_ENDPOINT" || key == "HEALTH_PATH" || key == "METRICS_PATH" {
			if val != "" && !strings.HasPrefix(val, "/health") && !strings.HasPrefix(val, "/ready") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "low",
					Rule:    "proberesist_status_endpoint",
					Message: fmt.Sprintf("Service '%s' exposes status endpoint at '%s' via %s; ensure it does not leak internal metrics", svc.Name, parts[1], parts[0]),
				})
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
			case "proberesist_debug_port", "proberesist_debug_enabled":
				s.DebugEndpoints++
			case "proberesist_version_header":
				s.VersionHeaders++
			case "proberesist_stack_trace":
				s.StackTraceLeaks++
			case "proberesist_status_endpoint":
				s.StatusEndpoints++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Probe Resistance Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Debug endpoints:     %d\n", r.Summary.DebugEndpoints)
	fmt.Fprintf(&b, "  Version headers:     %d\n", r.Summary.VersionHeaders)
	fmt.Fprintf(&b, "  Stack trace leaks:   %d\n", r.Summary.StackTraceLeaks)
	fmt.Fprintf(&b, "  Status endpoints:    %d\n\n", r.Summary.StatusEndpoints)
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
