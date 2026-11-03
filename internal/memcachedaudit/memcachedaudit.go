package memcachedaudit

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
	MissingAuth      int `json:"missing_auth"`
	PlaintextConn    int `json:"plaintext_connections"`
	ExposedPorts     int `json:"exposed_ports"`
	DefaultCreds     int `json:"default_credentials"`
	UDPEnabled       int `json:"udp_enabled"`
	LargeMemory      int `json:"large_memory_limit"`
}

var memcachedImages = []string{
	"memcached", "bitnami/memcached", "library/memcached",
	"amazon/elasticache", "memcachier",
}

func isMemcachedImage(image string) bool {
	lower := strings.ToLower(image)
	for _, mi := range memcachedImages {
		if strings.Contains(lower, mi) {
			return true
		}
	}
	return false
}

func getEnvValue(envs []string, key string) string {
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], key) {
			return parts[1]
		}
	}
	return ""
}

func hasEnvContaining(envs []string, substr string) bool {
	lower := strings.ToLower(substr)
	for _, e := range envs {
		if strings.Contains(strings.ToLower(e), lower) {
			return true
		}
	}
	return false
}

func isMemcachedPort(port compose.PortMapping) bool {
	return port.TargetPort == 11211 || port.TargetPort == 11212
}

func hasSASLAuth(envs []string, args string) bool {
	if hasEnvContaining(envs, "sasl") {
		return true
	}
	if hasEnvContaining(envs, "MEMCACHED_SASL_PWDB") {
		return true
	}
	if hasEnvContaining(envs, "MEMCACHED_USERNAME") {
		return true
	}
	if strings.Contains(strings.ToLower(args), "-s") && strings.Contains(strings.ToLower(args), "sasl") {
		return true
	}
	return false
}

func hasTLSConfig(envs []string) bool {
	if hasEnvContaining(envs, "tls") || hasEnvContaining(envs, "ssl") {
		return true
	}
	if hasEnvContaining(envs, "MEMCACHED_TLS_CERT") || hasEnvContaining(envs, "MEMCACHED_TLS_KEY") {
		return true
	}
	return false
}

var defaultCreds = []string{
	"admin:admin", "memcached:memcached", "admin:password",
	"admin:secret", "root:root", "cache:cache",
}

func hasDefaultCredentials(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		for _, cred := range defaultCreds {
			if strings.Contains(lower, cred) {
				return true
			}
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isMemcachedImage(svc.Image) {
		return sr
	}

	cmdArgs := strings.Join(svc.Command, " ")

	if !hasSASLAuth(svc.Environment, cmdArgs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "missing_auth",
			Message: fmt.Sprintf("Service '%s' Memcached has no SASL authentication; any client can read/write cache data", svc.Name),
		})
	}

	if !hasTLSConfig(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "plaintext_connection",
			Message: fmt.Sprintf("Service '%s' Memcached has no TLS configuration; cache traffic is transmitted in plaintext", svc.Name),
		})
	}

	for _, port := range svc.Ports {
		if isMemcachedPort(port) && port.IsAllInterfaces() {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "exposed_port",
				Message: fmt.Sprintf("Service '%s' exposes Memcached port %d on all interfaces", svc.Name, port.TargetPort),
			})
		}
	}

	if hasDefaultCredentials(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "default_credentials",
			Message: fmt.Sprintf("Service '%s' appears to use default credentials for Memcached authentication", svc.Name),
		})
	}

	if hasEnvContaining(svc.Environment, "udp") || strings.Contains(strings.ToLower(cmdArgs), "-u ") || strings.Contains(strings.ToLower(cmdArgs), "--udp") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "udp_enabled",
			Message: fmt.Sprintf("Service '%s' Memcached has UDP protocol enabled; susceptible to amplification attacks", svc.Name),
		})
	}

	memLimit := getEnvValue(svc.Environment, "MEMCACHED_MAX_MEMORY")
	if memLimit == "" {
		memLimit = getEnvValue(svc.Environment, "MEMCACHED_MEMORY_LIMIT")
	}
	if memLimit != "" {
		val := strings.TrimSuffix(strings.TrimSuffix(memLimit, "m"), "M")
		if len(val) >= 5 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "large_memory_limit",
				Message: fmt.Sprintf("Service '%s' Memcached configured with very large memory limit (%s); potential DoS vector", svc.Name, memLimit),
			})
		}
	}

	return sr
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
			case "missing_auth":
				s.MissingAuth++
			case "plaintext_connection":
				s.PlaintextConn++
			case "exposed_port":
				s.ExposedPorts++
			case "default_credentials":
				s.DefaultCreds++
			case "udp_enabled":
				s.UDPEnabled++
			case "large_memory_limit":
				s.LargeMemory++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Memcached Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Missing authentication:   %d\n", r.Summary.MissingAuth)
	fmt.Fprintf(&b, "  Plaintext connections:     %d\n", r.Summary.PlaintextConn)
	fmt.Fprintf(&b, "  Exposed ports:             %d\n", r.Summary.ExposedPorts)
	fmt.Fprintf(&b, "  Default credentials:       %d\n", r.Summary.DefaultCreds)
	fmt.Fprintf(&b, "  UDP enabled:               %d\n", r.Summary.UDPEnabled)
	fmt.Fprintf(&b, "  Large memory limits:       %d\n\n", r.Summary.LargeMemory)

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s (%s)\n", sr.Service, sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Level), f.Rule, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
