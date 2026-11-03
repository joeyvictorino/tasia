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
	Findings []Finding `json:"findings"`
}

type Summary struct {
	DefaultCredentials int `json:"default_credentials"`
	GuestAccess        int `json:"guest_access"`
	NoTLS              int `json:"no_tls"`
	ExposedPort        int `json:"exposed_port"`
	ManagementExposed  int `json:"management_exposed"`
	DebugEnabled       int `json:"debug_enabled"`
	NoAuthBackend      int `json:"no_auth_backend"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var rabbitmqImages = []string{
	"rabbitmq", "bitnami/rabbitmq", "pivotalrabbitmq/rabbitmq",
	"arm64v8/rabbitmq", "amd64/rabbitmq",
}

func isRabbitmqImage(image string) bool {
	img := strings.ToLower(image)
	for _, ri := range rabbitmqImages {
		if strings.Contains(img, ri) {
			return true
		}
	}
	return false
}

func hasDefaultCredentials(envs []string) bool {
	defaults := []string{"guest", "admin", "rabbitmq", "password", "changeme"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "rabbitmq_default_pass=") ||
			strings.Contains(lower, "rabbitmq_password=") {
			for _, d := range defaults {
				if strings.Contains(lower, "="+d) {
					return true
				}
			}
		}
	}
	return false
}

func hasGuestAccess(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "rabbitmq_default_user=guest") ||
			strings.Contains(lower, "loopback_users=none") ||
			strings.Contains(lower, "loopback_users.guest=false") {
			return true
		}
	}
	return false
}

func hasNoTLS(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "ssl=false") ||
			strings.Contains(lower, "tls=false") ||
			strings.Contains(lower, "rabbitmq_ssl=false") {
			return true
		}
	}
	return false
}

func hasDebugEnabled(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "log_level=debug") ||
			strings.Contains(lower, "rabbitmq_log=debug") ||
			(strings.Contains(lower, "debug") && strings.Contains(lower, "=true")) {
			return true
		}
	}
	return false
}

func hasNoAuthBackend(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "auth_backends=none") ||
			strings.Contains(lower, "auth_backend=none") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	if hasDefaultCredentials(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "rabbitmq_default_credentials",
			Message: fmt.Sprintf("service %q: RabbitMQ using default/weak credentials", svc.Name),
		})
	}

	if hasGuestAccess(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "rabbitmq_guest_access",
			Message: fmt.Sprintf("service %q: RabbitMQ guest user enabled for remote access", svc.Name),
		})
	}

	if hasNoTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "rabbitmq_no_tls",
			Message: fmt.Sprintf("service %q: RabbitMQ TLS/SSL disabled", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		5672:  "AMQP",
		5671:  "AMQPS",
		15672: "Management UI",
		15671: "Management UI (TLS)",
		25672: "Erlang distribution",
		4369:  "EPMD",
		61613: "STOMP",
		15674: "WebSTOMP",
		1883:  "MQTT",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				if p.TargetPort == 15672 || p.TargetPort == 15671 {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "critical",
						Rule:    "rabbitmq_management_exposed",
						Message: fmt.Sprintf("service %q: RabbitMQ %s exposed on all interfaces", svc.Name, desc),
					})
				} else {
					sr.Findings = append(sr.Findings, Finding{
						Level:   "high",
						Rule:    "rabbitmq_exposed_port",
						Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
					})
				}
			}
		}
	}

	if hasDebugEnabled(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "rabbitmq_debug_enabled",
			Message: fmt.Sprintf("service %q: RabbitMQ debug logging enabled", svc.Name),
		})
	}

	if hasNoAuthBackend(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "rabbitmq_no_auth_backend",
			Message: fmt.Sprintf("service %q: RabbitMQ authentication backend disabled", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isRabbitmqImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "rabbitmq_default_credentials":
					r.Summary.DefaultCredentials++
				case "rabbitmq_guest_access":
					r.Summary.GuestAccess++
				case "rabbitmq_no_tls":
					r.Summary.NoTLS++
				case "rabbitmq_exposed_port":
					r.Summary.ExposedPort++
				case "rabbitmq_management_exposed":
					r.Summary.ManagementExposed++
				case "rabbitmq_debug_enabled":
					r.Summary.DebugEnabled++
				case "rabbitmq_no_auth_backend":
					r.Summary.NoAuthBackend++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("RabbitMQ Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No RabbitMQ services found.\n")
		return b.String()
	}

	for _, svc := range r.Services {
		fmt.Fprintf(&b, "  Service: %s\n", svc.Service)
		if len(svc.Findings) == 0 {
			b.WriteString("    No findings.\n")
		}
		for _, f := range svc.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Level, f.Rule, f.Message)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "  Summary: default_creds=%d guest=%d no_tls=%d exposed=%d mgmt=%d debug=%d no_auth=%d\n",
		r.Summary.DefaultCredentials, r.Summary.GuestAccess, r.Summary.NoTLS,
		r.Summary.ExposedPort, r.Summary.ManagementExposed, r.Summary.DebugEnabled, r.Summary.NoAuthBackend)

	return b.String()
}
