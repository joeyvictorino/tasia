package postgresaudit

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
	NoPassword         int `json:"no_password"`
	TrustAuth          int `json:"trust_auth"`
	DefaultCredentials int `json:"default_credentials"`
	ExposedPort        int `json:"exposed_port"`
	NoSSL              int `json:"no_ssl"`
	SuperuserExposed   int `json:"superuser_exposed"`
}

var postgresImages = []string{
	"postgres", "bitnami/postgresql", "postgis/postgis",
	"timescale/timescaledb", "citusdata/citus",
}

func isPostgresImage(image string) bool {
	lower := strings.ToLower(image)
	for _, pi := range postgresImages {
		if strings.Contains(lower, pi) {
			return true
		}
	}
	return false
}

func getEnvVal(envs []string, key string) (string, bool) {
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], key) {
			return parts[1], true
		}
	}
	return "", false
}

func hasEnvKey(envs []string, key string) bool {
	_, ok := getEnvVal(envs, key)
	return ok
}

var defaultPasswords = []string{
	"postgres", "password", "123456", "admin",
	"changeme", "secret", "root", "default",
}

var defaultUsernames = []string{
	"postgres", "admin", "root", "user",
}

func hasDefaultCredentials(envs []string) bool {
	if pw, ok := getEnvVal(envs, "POSTGRES_PASSWORD"); ok {
		lower := strings.ToLower(pw)
		for _, dp := range defaultPasswords {
			if lower == dp {
				return true
			}
		}
	}
	if user, ok := getEnvVal(envs, "POSTGRES_USER"); ok {
		lower := strings.ToLower(user)
		for _, du := range defaultUsernames {
			if lower == du {
				if pw, pok := getEnvVal(envs, "POSTGRES_PASSWORD"); pok {
					pwLower := strings.ToLower(pw)
					for _, dp := range defaultPasswords {
						if pwLower == dp {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func hasSSLConfig(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "ssl=on") ||
			strings.Contains(lower, "sslmode=") ||
			strings.Contains(lower, "ssl_cert_file") ||
			strings.Contains(lower, "ssl_key_file") ||
			strings.Contains(lower, "pgsslmode") ||
			strings.Contains(lower, "pgsslcert") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isPostgresImage(svc.Image) {
		return sr
	}

	hasPW := hasEnvKey(svc.Environment, "POSTGRES_PASSWORD")
	authMethod, hasAuth := getEnvVal(svc.Environment, "POSTGRES_HOST_AUTH_METHOD")

	if hasAuth && strings.EqualFold(authMethod, "trust") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "trust_auth",
			Message: fmt.Sprintf("Service '%s' uses POSTGRES_HOST_AUTH_METHOD=trust; any client can connect without a password", svc.Name),
		})
	}

	if !hasPW && !hasAuth {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "no_password",
			Message: fmt.Sprintf("Service '%s' PostgreSQL has no POSTGRES_PASSWORD set and no explicit auth method", svc.Name),
		})
	}

	if hasDefaultCredentials(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "default_credentials",
			Message: fmt.Sprintf("Service '%s' PostgreSQL uses default or well-known credentials", svc.Name),
		})
	}

	for _, port := range svc.Ports {
		if port.TargetPort == 5432 && port.IsAllInterfaces() {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "exposed_port",
				Message: fmt.Sprintf("Service '%s' exposes PostgreSQL port 5432 on all interfaces", svc.Name),
			})
		}
	}

	if !hasSSLConfig(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "no_ssl",
			Message: fmt.Sprintf("Service '%s' PostgreSQL has no SSL/TLS configuration", svc.Name),
		})
	}

	if !hasEnvKey(svc.Environment, "POSTGRES_USER") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "superuser_exposed",
			Message: fmt.Sprintf("Service '%s' does not set POSTGRES_USER; defaults to superuser 'postgres'", svc.Name),
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
			case "no_password":
				s.NoPassword++
			case "trust_auth":
				s.TrustAuth++
			case "default_credentials":
				s.DefaultCredentials++
			case "exposed_port":
				s.ExposedPort++
			case "no_ssl":
				s.NoSSL++
			case "superuser_exposed":
				s.SuperuserExposed++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "PostgreSQL Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No password:            %d\n", r.Summary.NoPassword)
	fmt.Fprintf(&b, "  Trust auth:             %d\n", r.Summary.TrustAuth)
	fmt.Fprintf(&b, "  Default credentials:    %d\n", r.Summary.DefaultCredentials)
	fmt.Fprintf(&b, "  Exposed ports:          %d\n", r.Summary.ExposedPort)
	fmt.Fprintf(&b, "  No SSL:                 %d\n", r.Summary.NoSSL)
	fmt.Fprintf(&b, "  Superuser exposed:      %d\n\n", r.Summary.SuperuserExposed)
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
