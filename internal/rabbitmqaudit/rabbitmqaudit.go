package rabbitmqaudit

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
	DefaultCreds     int `json:"default_creds"`
	ExposedMgmt      int `json:"exposed_mgmt"`
	UnencryptedAMQP  int `json:"unencrypted_amqp"`
	MissingUserOverride int `json:"missing_user_override"`
	ExposedCookie    int `json:"exposed_cookie"`
	MissingSSL       int `json:"missing_ssl"`
}

var rabbitmqImages = []string{
	"rabbitmq", "bitnami/rabbitmq", "pivotalrabbitmq",
}

func isRabbitmqImage(image string) bool {
	lower := strings.ToLower(image)
	for _, ri := range rabbitmqImages {
		if strings.Contains(lower, ri) {
			return true
		}
	}
	return false
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

func getEnvValue(envs []string, key string) string {
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], key) {
			return parts[1]
		}
	}
	return ""
}

func hasDefaultCredentials(envs []string) bool {
	user := getEnvValue(envs, "RABBITMQ_DEFAULT_USER")
	pass := getEnvValue(envs, "RABBITMQ_DEFAULT_PASS")
	if user == "" && pass == "" {
		return true
	}
	if strings.EqualFold(user, "guest") && strings.EqualFold(pass, "guest") {
		return true
	}
	defaults := []string{"guest", "admin", "password", "123456", "rabbitmq"}
	for _, d := range defaults {
		if strings.EqualFold(pass, d) {
			return true
		}
	}
	return false
}

func hasUserOverride(envs []string) bool {
	return hasEnvKey(envs, "RABBITMQ_DEFAULT_USER")
}

func hasSSLConfig(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "ssl") || strings.Contains(lower, "tls") {
			return true
		}
	}
	sslVars := []string{
		"RABBITMQ_SSL_CERTFILE",
		"RABBITMQ_SSL_KEYFILE",
		"RABBITMQ_SSL_CACERTFILE",
		"RABBITMQ_SSL_FAIL_IF_NO_PEER_CERT",
	}
	for _, k := range sslVars {
		if hasEnvKey(envs, k) {
			return true
		}
	}
	return false
}

func hasCookieExposed(envs []string) bool {
	return hasEnvKey(envs, "RABBITMQ_ERLANG_COOKIE")
}

func isMgmtPort(port compose.PortMapping) bool {
	return port.TargetPort == 15672 || port.TargetPort == 15671
}

func isAMQPPort(port compose.PortMapping) bool {
	return port.TargetPort == 5672
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isRabbitmqImage(svc.Image) {
		return sr
	}

	if hasDefaultCredentials(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "default_creds",
			Message: fmt.Sprintf("Service '%s' RabbitMQ uses default or well-known credentials", svc.Name),
		})
	}

	for _, port := range svc.Ports {
		if isMgmtPort(port) && port.IsAllInterfaces() {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "exposed_mgmt",
				Message: fmt.Sprintf("Service '%s' exposes RabbitMQ management UI port %d on all interfaces", svc.Name, port.TargetPort),
			})
		}
		if isAMQPPort(port) && port.IsAllInterfaces() && !hasSSLConfig(svc.Environment) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "unencrypted_amqp",
				Message: fmt.Sprintf("Service '%s' exposes unencrypted AMQP port %d without TLS", svc.Name, port.TargetPort),
			})
		}
	}

	if !hasUserOverride(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "missing_user_override",
			Message: fmt.Sprintf("Service '%s' RabbitMQ has no RABBITMQ_DEFAULT_USER override; defaults to guest", svc.Name),
		})
	}

	if hasCookieExposed(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "exposed_cookie",
			Message: fmt.Sprintf("Service '%s' exposes RABBITMQ_ERLANG_COOKIE in environment variables", svc.Name),
		})
	}

	if !hasSSLConfig(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "missing_ssl",
			Message: fmt.Sprintf("Service '%s' RabbitMQ has no SSL/TLS certificate configuration", svc.Name),
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
			case "default_creds":
				s.DefaultCreds++
			case "exposed_mgmt":
				s.ExposedMgmt++
			case "unencrypted_amqp":
				s.UnencryptedAMQP++
			case "missing_user_override":
				s.MissingUserOverride++
			case "exposed_cookie":
				s.ExposedCookie++
			case "missing_ssl":
				s.MissingSSL++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "RabbitMQ Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Default credentials:        %d\n", r.Summary.DefaultCreds)
	fmt.Fprintf(&b, "  Exposed management UI:      %d\n", r.Summary.ExposedMgmt)
	fmt.Fprintf(&b, "  Unencrypted AMQP:           %d\n", r.Summary.UnencryptedAMQP)
	fmt.Fprintf(&b, "  Missing user override:      %d\n", r.Summary.MissingUserOverride)
	fmt.Fprintf(&b, "  Exposed Erlang cookie:      %d\n", r.Summary.ExposedCookie)
	fmt.Fprintf(&b, "  Missing SSL/TLS:            %d\n\n", r.Summary.MissingSSL)
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
