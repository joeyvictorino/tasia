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
	NoTLS              int `json:"no_tls"`
	ManagementExposed  int `json:"management_exposed"`
	ExposedPort        int `json:"exposed_port"`
	GuestLoopback      int `json:"guest_loopback"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var rabbitmqImages = []string{
	"rabbitmq", "bitnami/rabbitmq",
}

func isRabbitMQImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range rabbitmqImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasDefaultCredentials(envs []string) bool {
	defaults := []string{"guest", "admin", "password", "changeme", "rabbitmq"}
	user := ""
	pass := ""
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.HasPrefix(lower, "rabbitmq_default_user=") {
			user = strings.TrimPrefix(lower, "rabbitmq_default_user=")
		}
		if strings.HasPrefix(lower, "rabbitmq_default_pass=") {
			pass = strings.TrimPrefix(lower, "rabbitmq_default_pass=")
		}
	}
	if user == "guest" && pass == "guest" {
		return true
	}
	for _, d := range defaults {
		if pass == d {
			return true
		}
	}
	if user == "" && pass == "" {
		return true
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "RABBITMQ_SSL_CERTFILE") ||
			strings.Contains(upper, "RABBITMQ_SSL_CACERTFILE") ||
			strings.Contains(upper, "RABBITMQ_SSL_KEYFILE") ||
			strings.Contains(upper, "RABBITMQ_CTL_ERL_ARGS") && strings.Contains(upper, "SSL") {
			return true
		}
	}
	return false
}

func hasManagementExposed(envs []string, ports []compose.PortMapping) bool {
	for _, p := range ports {
		if p.TargetPort == 15672 && p.IsAllInterfaces() {
			hasCredentials := false
			for _, e := range envs {
				lower := strings.ToLower(e)
				if strings.HasPrefix(lower, "rabbitmq_default_user=") &&
					!strings.HasSuffix(lower, "=guest") {
					hasCredentials = true
				}
			}
			if !hasCredentials {
				return true
			}
		}
	}
	return false
}

func hasGuestLoopbackDisabled(envs []string, ports []compose.PortMapping) bool {
	loopbackNone := false
	hasExposedPort := false
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "rabbitmq_loopback_users=none") ||
			strings.Contains(lower, "loopback_users.guest=false") {
			loopbackNone = true
		}
	}
	for _, p := range ports {
		if (p.TargetPort == 5672 || p.TargetPort == 15672) && p.IsAllInterfaces() {
			hasExposedPort = true
		}
	}
	return loopbackNone && hasExposedPort
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	if hasDefaultCredentials(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "rabbitmq_default_credentials",
			Message: fmt.Sprintf("service %q: RabbitMQ using default or weak credentials", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "rabbitmq_no_tls",
			Message: fmt.Sprintf("service %q: RabbitMQ running without TLS encryption", svc.Name),
		})
	}

	if hasManagementExposed(envs, svc.Ports) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "rabbitmq_management_exposed",
			Message: fmt.Sprintf("service %q: RabbitMQ management UI exposed without custom credentials", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		5672:  "RabbitMQ AMQP",
		5671:  "RabbitMQ AMQPS",
		15672: "RabbitMQ Management",
		25672: "RabbitMQ Clustering",
		61613: "RabbitMQ STOMP",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "rabbitmq_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasGuestLoopbackDisabled(envs, svc.Ports) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "rabbitmq_guest_loopback",
			Message: fmt.Sprintf("service %q: RabbitMQ guest loopback restriction disabled with exposed ports", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isRabbitMQImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "rabbitmq_default_credentials":
					r.Summary.DefaultCredentials++
				case "rabbitmq_no_tls":
					r.Summary.NoTLS++
				case "rabbitmq_management_exposed":
					r.Summary.ManagementExposed++
				case "rabbitmq_exposed_port":
					r.Summary.ExposedPort++
				case "rabbitmq_guest_loopback":
					r.Summary.GuestLoopback++
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

	fmt.Fprintf(&b, "  Summary: default_credentials=%d no_tls=%d management_exposed=%d exposed_port=%d guest_loopback=%d\n",
		r.Summary.DefaultCredentials, r.Summary.NoTLS, r.Summary.ManagementExposed,
		r.Summary.ExposedPort, r.Summary.GuestLoopback)

	return b.String()
}
