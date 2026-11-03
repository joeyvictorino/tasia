package redisaudit

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
	NoAuth           int `json:"no_auth"`
	ExposedPort      int `json:"exposed_port"`
	MissingTLS       int `json:"missing_tls"`
	DangerousCommand int `json:"dangerous_command"`
	DefaultPassword  int `json:"default_password"`
	NoMaxMemPolicy   int `json:"no_maxmem_policy"`
}

var redisImages = []string{
	"redis", "bitnami/redis", "redis/redis-stack",
	"eqalpha/keydb", "dragonfly",
}

func isRedisImage(image string) bool {
	lower := strings.ToLower(image)
	for _, ri := range redisImages {
		if strings.Contains(lower, ri) {
			return true
		}
	}
	return false
}

var authVars = []string{
	"REDIS_PASSWORD",
	"REDIS_REQUIREPASS",
	"REDIS_AUTH",
	"REDIS_DEFAULT_PASSWORD",
	"REDIS_ACL_FILE",
}

var tlsVars = []string{
	"REDIS_TLS_ENABLED",
	"REDIS_TLS_PORT",
	"REDIS_TLS_CERT_FILE",
	"REDIS_TLS_KEY_FILE",
	"REDIS_TLS_CA_FILE",
}

var defaultPasswords = []string{
	"redis", "password", "123456", "default",
	"changeme", "secret", "admin", "root",
}

func hasEnvKey(envs []string, key string) bool {
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) >= 1 && strings.EqualFold(parts[0], key) {
			return true
		}
	}
	return false
}

func hasAuthConfig(envs []string) bool {
	for _, k := range authVars {
		if hasEnvKey(envs, k) {
			return true
		}
	}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "requirepass") || strings.Contains(lower, "--requirepass") {
			return true
		}
	}
	return false
}

func hasTLSConfig(envs []string) bool {
	for _, k := range tlsVars {
		if hasEnvKey(envs, k) {
			return true
		}
	}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "tls-cert-file") || strings.Contains(lower, "tls-key-file") {
			return true
		}
	}
	return false
}

func hasMaxMemPolicy(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "maxmemory-policy") || strings.Contains(lower, "maxmemory_policy") {
			return true
		}
	}
	return false
}

func hasDefaultPassword(envs []string) bool {
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		val := strings.ToLower(parts[1])
		for _, dp := range defaultPasswords {
			if val == dp {
				return true
			}
		}
	}
	return false
}

func isRedisPort(port compose.PortMapping) bool {
	return port.TargetPort == 6379 || port.TargetPort == 6380
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isRedisImage(svc.Image) {
		return sr
	}

	if !hasAuthConfig(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "no_auth",
			Message: fmt.Sprintf("Service '%s' Redis has no authentication configured; any client can connect and execute commands", svc.Name),
		})
	}

	for _, port := range svc.Ports {
		if isRedisPort(port) && port.IsAllInterfaces() {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "exposed_port",
				Message: fmt.Sprintf("Service '%s' exposes Redis port %d on all interfaces", svc.Name, port.TargetPort),
			})
		}
	}

	if !hasTLSConfig(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "missing_tls",
			Message: fmt.Sprintf("Service '%s' Redis has no TLS configuration; data is transmitted unencrypted", svc.Name),
		})
	}

	if hasDefaultPassword(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "default_password",
			Message: fmt.Sprintf("Service '%s' Redis uses a default or well-known password", svc.Name),
		})
	}

	if !hasMaxMemPolicy(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "no_maxmem_policy",
			Message: fmt.Sprintf("Service '%s' Redis has no maxmemory-policy set; may run out of memory under load", svc.Name),
		})
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
			case "no_auth":
				s.NoAuth++
			case "exposed_port":
				s.ExposedPort++
			case "missing_tls":
				s.MissingTLS++
			case "dangerous_command":
				s.DangerousCommand++
			case "default_password":
				s.DefaultPassword++
			case "no_maxmem_policy":
				s.NoMaxMemPolicy++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Redis Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No authentication:      %d\n", r.Summary.NoAuth)
	fmt.Fprintf(&b, "  Exposed ports:          %d\n", r.Summary.ExposedPort)
	fmt.Fprintf(&b, "  Missing TLS:            %d\n", r.Summary.MissingTLS)
	fmt.Fprintf(&b, "  Dangerous commands:     %d\n", r.Summary.DangerousCommand)
	fmt.Fprintf(&b, "  Default passwords:      %d\n", r.Summary.DefaultPassword)
	fmt.Fprintf(&b, "  No maxmemory policy:    %d\n\n", r.Summary.NoMaxMemPolicy)
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
