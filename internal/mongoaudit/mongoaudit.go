package mongoaudit

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
	NoAuth             int `json:"no_auth"`
	DefaultCredentials int `json:"default_credentials"`
	ExposedPort        int `json:"exposed_port"`
	NoTLS              int `json:"no_tls"`
	BindAllInterfaces  int `json:"bind_all_interfaces"`
}

var mongoImages = []string{
	"mongo", "bitnami/mongodb", "percona/percona-server-mongodb",
	"mongodb/mongodb-community-server", "circleci/mongo",
}

var authVars = []string{
	"MONGO_INITDB_ROOT_USERNAME",
	"MONGODB_ROOT_USER",
	"MONGODB_ROOT_USERNAME",
	"MONGODB_EXTRA_USERNAMES",
	"MONGO_USERNAME",
}

var passwordVars = []string{
	"MONGO_INITDB_ROOT_PASSWORD",
	"MONGODB_ROOT_PASSWORD",
	"MONGO_PASSWORD",
	"MONGODB_EXTRA_PASSWORDS",
}

var defaultCredentials = []string{
	"admin", "root", "mongo", "password",
	"changeme", "secret", "12345", "123456",
	"test", "mongodb",
}

var tlsVars = []string{
	"MONGODB_EXTRA_FLAGS",
	"MONGO_TLS",
	"MONGODB_TLS_ENABLED",
	"MONGODB_EXTRA_FLAGS",
}

func isMongoImage(image string) bool {
	lower := strings.ToLower(image)
	for _, mi := range mongoImages {
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

func hasEnvKey(envs []string, key string) bool {
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) >= 1 && strings.EqualFold(parts[0], key) {
			return true
		}
	}
	return false
}

func hasAuthConfig(svc compose.Service) bool {
	for _, k := range authVars {
		if hasEnvKey(svc.Environment, k) {
			return true
		}
	}
	for _, cmd := range svc.Command {
		if strings.Contains(cmd, "--auth") {
			return true
		}
	}
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "auth") && !strings.Contains(lower, "noauth") {
			return true
		}
	}
	return false
}

func hasDefaultCredentials(envs []string) bool {
	for _, k := range passwordVars {
		val := getEnvValue(envs, k)
		if val == "" {
			continue
		}
		lower := strings.ToLower(val)
		for _, dc := range defaultCredentials {
			if lower == dc {
				return true
			}
		}
	}
	for _, k := range authVars {
		val := getEnvValue(envs, k)
		if val == "" {
			continue
		}
		lower := strings.ToLower(val)
		for _, dc := range defaultCredentials {
			if lower == dc {
				return true
			}
		}
	}
	return false
}

func hasTLSConfig(svc compose.Service) bool {
	for _, k := range tlsVars {
		val := getEnvValue(svc.Environment, k)
		if val != "" && (strings.Contains(strings.ToLower(val), "tls") || strings.Contains(strings.ToLower(val), "ssl")) {
			return true
		}
	}
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "tls") || strings.Contains(lower, "ssl") {
			return true
		}
	}
	for _, cmd := range svc.Command {
		if strings.Contains(cmd, "--tls") || strings.Contains(cmd, "--sslMode") {
			return true
		}
	}
	return false
}

func hasBindAllInterfaces(svc compose.Service) bool {
	for _, cmd := range svc.Command {
		if strings.Contains(cmd, "--bind_ip_all") {
			return true
		}
		if strings.Contains(cmd, "bindIp=0.0.0.0") || strings.Contains(cmd, "bind_ip=0.0.0.0") {
			return true
		}
	}
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "bind_ip_all") || strings.Contains(lower, "bindip=0.0.0.0") {
			return true
		}
	}
	return false
}

func isMongoPort(port compose.PortMapping) bool {
	return port.TargetPort == 27017 || port.TargetPort == 27018 || port.TargetPort == 27019
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isMongoImage(svc.Image) {
		return sr
	}

	if !hasAuthConfig(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "no_auth",
			Message: fmt.Sprintf("Service '%s' runs MongoDB without authentication; any client can read and write all databases", svc.Name),
		})
	}

	if hasDefaultCredentials(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "default_credentials",
			Message: fmt.Sprintf("Service '%s' uses common default MongoDB credentials", svc.Name),
		})
	}

	for _, port := range svc.Ports {
		if isMongoPort(port) && port.IsAllInterfaces() {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "exposed_port",
				Message: fmt.Sprintf("Service '%s' exposes MongoDB port %d on all interfaces", svc.Name, port.TargetPort),
			})
		}
	}

	if !hasTLSConfig(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "no_tls",
			Message: fmt.Sprintf("Service '%s' MongoDB has no TLS/SSL configuration; traffic is unencrypted", svc.Name),
		})
	}

	if hasBindAllInterfaces(svc) && !hasAuthConfig(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "bind_all_interfaces",
			Message: fmt.Sprintf("Service '%s' MongoDB binds to all interfaces without authentication", svc.Name),
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
			case "default_credentials":
				s.DefaultCredentials++
			case "exposed_port":
				s.ExposedPort++
			case "no_tls":
				s.NoTLS++
			case "bind_all_interfaces":
				s.BindAllInterfaces++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "MongoDB Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No authentication:     %d\n", r.Summary.NoAuth)
	fmt.Fprintf(&b, "  Default credentials:   %d\n", r.Summary.DefaultCredentials)
	fmt.Fprintf(&b, "  Exposed ports:         %d\n", r.Summary.ExposedPort)
	fmt.Fprintf(&b, "  No TLS/SSL:            %d\n", r.Summary.NoTLS)
	fmt.Fprintf(&b, "  Bind all interfaces:   %d\n\n", r.Summary.BindAllInterfaces)
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
