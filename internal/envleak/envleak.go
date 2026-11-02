package envleak

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type LeakPath struct {
	SourceService string   `json:"source_service"`
	TargetService string   `json:"target_service"`
	Mechanism     string   `json:"mechanism"`
	EnvVars       []string `json:"env_vars,omitempty"`
	Severity      string   `json:"severity"`
	Detail        string   `json:"detail"`
}

type Summary struct {
	TotalServices  int `json:"total_services"`
	TotalLeakPaths int `json:"total_leak_paths"`
	HighRiskCount  int `json:"high_risk_count"`
}

type Report struct {
	Paths   []LeakPath `json:"paths"`
	Summary Summary    `json:"summary"`
}

var sensitivePatterns = []string{
	"password", "secret", "token", "key", "api_key", "apikey",
	"auth", "credential", "private", "jwt", "session",
	"database_url", "db_pass", "redis_pass", "mongo_uri",
}

func Analyze(c *collect.Collected) Report {
	var paths []LeakPath

	for _, comp := range c.ComposeFiles {
		svcMap := buildServiceMap(comp.Services)
		for _, svc := range comp.Services {
			paths = append(paths, checkNetworkMode(svc, svcMap)...)
			paths = append(paths, checkPidMode(svc, svcMap)...)
		}
	}

	high := 0
	for _, p := range paths {
		if p.Severity == "high" || p.Severity == "critical" {
			high++
		}
	}

	total := 0
	for _, comp := range c.ComposeFiles {
		total += len(comp.Services)
	}

	return Report{
		Paths: paths,
		Summary: Summary{
			TotalServices:  total,
			TotalLeakPaths: len(paths),
			HighRiskCount:  high,
		},
	}
}

func buildServiceMap(services []compose.Service) map[string]compose.Service {
	m := make(map[string]compose.Service, len(services))
	for _, s := range services {
		m[s.Name] = s
	}
	return m
}

func checkNetworkMode(svc compose.Service, svcMap map[string]compose.Service) []LeakPath {
	if !strings.HasPrefix(svc.NetworkMode, "service:") {
		return nil
	}
	target := strings.TrimPrefix(svc.NetworkMode, "service:")
	targetSvc, ok := svcMap[target]
	if !ok {
		return nil
	}

	sensitiveVars := findSensitiveVars(targetSvc.Environment)
	sev := "medium"
	if len(sensitiveVars) > 0 {
		sev = "high"
	}

	return []LeakPath{{
		SourceService: target,
		TargetService: svc.Name,
		Mechanism:     "shared_network_namespace",
		EnvVars:       sensitiveVars,
		Severity:      sev,
		Detail:        fmt.Sprintf("Service %q shares network namespace with %q via network_mode, exposing localhost services and potentially environment variables", svc.Name, target),
	}}
}

func checkPidMode(svc compose.Service, svcMap map[string]compose.Service) []LeakPath {
	if !strings.HasPrefix(svc.PidMode, "service:") {
		return nil
	}
	target := strings.TrimPrefix(svc.PidMode, "service:")
	targetSvc, ok := svcMap[target]
	if !ok {
		return nil
	}

	sensitiveVars := findSensitiveVars(targetSvc.Environment)
	sev := "high"
	if len(sensitiveVars) > 0 {
		sev = "critical"
	}

	return []LeakPath{{
		SourceService: target,
		TargetService: svc.Name,
		Mechanism:     "shared_pid_namespace",
		EnvVars:       sensitiveVars,
		Severity:      sev,
		Detail:        fmt.Sprintf("Service %q shares PID namespace with %q via pid mode, allowing /proc/<pid>/environ access to environment variables", svc.Name, target),
	}}
}

func findSensitiveVars(envVars []string) []string {
	var sensitive []string
	for _, e := range envVars {
		parts := strings.SplitN(e, "=", 2)
		key := strings.ToLower(parts[0])
		for _, pattern := range sensitivePatterns {
			if strings.Contains(key, pattern) {
				sensitive = append(sensitive, parts[0])
				break
			}
		}
	}
	return sensitive
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Environment Variable Leak Analysis\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&sb, "  Services:    %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&sb, "  Leak paths:  %d\n", r.Summary.TotalLeakPaths)
	fmt.Fprintf(&sb, "  High risk:   %d\n\n", r.Summary.HighRiskCount)

	for _, p := range r.Paths {
		fmt.Fprintf(&sb, "  [%s] %s -> %s (%s)\n", p.Severity, p.SourceService, p.TargetService, p.Mechanism)
		sb.WriteString("    " + p.Detail + "\n")
		if len(p.EnvVars) > 0 {
			fmt.Fprintf(&sb, "    Sensitive vars: %s\n", strings.Join(p.EnvVars, ", "))
		}
	}
	return sb.String()
}

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
