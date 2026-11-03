package mysqlaudit

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
	EmptyRootPassword  int `json:"empty_root_password"`
	DefaultCredentials int `json:"default_credentials"`
	ExposedPort        int `json:"exposed_port"`
	NoSSL              int `json:"no_ssl"`
	RandomRootPassword int `json:"random_root_password"`
}

var mysqlImages = []string{
	"mysql", "mariadb", "bitnami/mysql",
	"bitnami/mariadb", "percona",
}

func isMySQLImage(image string) bool {
	lower := strings.ToLower(image)
	for _, mi := range mysqlImages {
		if strings.Contains(lower, mi) {
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
	"mysql", "password", "123456", "admin",
	"changeme", "secret", "root", "default",
	"mariadb", "percona",
}

func hasSSLConfig(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "ssl-ca") ||
			strings.Contains(lower, "ssl-cert") ||
			strings.Contains(lower, "ssl-key") ||
			strings.Contains(lower, "require_secure_transport") ||
			strings.Contains(lower, "mysql_ssl") ||
			strings.Contains(lower, "tls_version") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isMySQLImage(svc.Image) {
		return sr
	}

	if val, ok := getEnvVal(svc.Environment, "MYSQL_ALLOW_EMPTY_PASSWORD"); ok {
		if strings.EqualFold(val, "yes") || val == "1" || strings.EqualFold(val, "true") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "empty_root_password",
				Message: fmt.Sprintf("Service '%s' MySQL allows empty root password", svc.Name),
			})
		}
	}

	if pw, ok := getEnvVal(svc.Environment, "MYSQL_ROOT_PASSWORD"); ok {
		lower := strings.ToLower(pw)
		for _, dp := range defaultPasswords {
			if lower == dp {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "default_credentials",
					Message: fmt.Sprintf("Service '%s' MySQL uses a default or well-known root password", svc.Name),
				})
				break
			}
		}
	}

	for _, port := range svc.Ports {
		if port.TargetPort == 3306 && port.IsAllInterfaces() {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "exposed_port",
				Message: fmt.Sprintf("Service '%s' exposes MySQL port 3306 on all interfaces", svc.Name),
			})
		}
	}

	if !hasSSLConfig(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "no_ssl",
			Message: fmt.Sprintf("Service '%s' MySQL has no SSL/TLS configuration", svc.Name),
		})
	}

	if !hasEnvKey(svc.Environment, "MYSQL_RANDOM_ROOT_PASSWORD") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "random_root_password",
			Message: fmt.Sprintf("Service '%s' does not use MYSQL_RANDOM_ROOT_PASSWORD; consider using it for production", svc.Name),
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
			case "empty_root_password":
				s.EmptyRootPassword++
			case "default_credentials":
				s.DefaultCredentials++
			case "exposed_port":
				s.ExposedPort++
			case "no_ssl":
				s.NoSSL++
			case "random_root_password":
				s.RandomRootPassword++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "MySQL Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Empty root password:    %d\n", r.Summary.EmptyRootPassword)
	fmt.Fprintf(&b, "  Default credentials:    %d\n", r.Summary.DefaultCredentials)
	fmt.Fprintf(&b, "  Exposed ports:          %d\n", r.Summary.ExposedPort)
	fmt.Fprintf(&b, "  No SSL:                 %d\n", r.Summary.NoSSL)
	fmt.Fprintf(&b, "  No random root pass:    %d\n\n", r.Summary.RandomRootPassword)
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
