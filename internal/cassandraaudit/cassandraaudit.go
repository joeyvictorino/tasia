package cassandraaudit

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
	NoAuth          int `json:"no_auth"`
	NoTLS           int `json:"no_tls"`
	ExposedPort     int `json:"exposed_port"`
	DefaultPassword int `json:"default_password"`
	JMXExposed      int `json:"jmx_exposed"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var cassandraImages = []string{
	"cassandra", "bitnami/cassandra",
}

func isCassandraImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range cassandraImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasAuth(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "CASSANDRA_AUTHENTICATOR=ALLOWALLAUTHENTICATOR") {
			return false
		}
		if strings.Contains(upper, "CASSANDRA_AUTHORIZER=ALLOWALLAUTHORIZER") {
			return false
		}
	}
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "CASSANDRA_AUTHENTICATOR=PASSWORDAUTHENTICATOR") {
			return true
		}
		if strings.Contains(upper, "CASSANDRA_PASSWORD=") {
			return true
		}
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "CASSANDRA_CLIENT_ENCRYPTION") ||
			strings.Contains(upper, "CASSANDRA_SSL") ||
			strings.Contains(upper, "CASSANDRA_INTERNODE_ENCRYPTION") ||
			strings.Contains(upper, "CASSANDRA_TRUSTSTORE") ||
			strings.Contains(upper, "CASSANDRA_KEYSTORE") {
			return true
		}
	}
	return false
}

func hasDefaultPassword(envs []string) bool {
	defaults := []string{"cassandra", "admin", "password", "changeme", "default", "test"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.HasPrefix(lower, "cassandra_password=") {
			pw := strings.TrimPrefix(lower, "cassandra_password=")
			for _, d := range defaults {
				if pw == d {
					return true
				}
			}
		}
		if strings.HasPrefix(lower, "cassandra_password_seeder=") {
			pw := strings.TrimPrefix(lower, "cassandra_password_seeder=")
			for _, d := range defaults {
				if pw == d {
					return true
				}
			}
		}
	}
	return false
}

func hasJMXExposed(envs []string, ports []compose.PortMapping) bool {
	for _, p := range ports {
		if p.TargetPort == 7199 && p.IsAllInterfaces() {
			for _, e := range envs {
				upper := strings.ToUpper(e)
				if strings.Contains(upper, "LOCAL_JMX=NO") ||
					strings.Contains(upper, "JMX_PORT=") {
					return true
				}
			}
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	if !hasAuth(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "cassandra_no_auth",
			Message: fmt.Sprintf("service %q: Cassandra authentication disabled or not configured", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "cassandra_no_tls",
			Message: fmt.Sprintf("service %q: Cassandra running without TLS encryption", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		9042: "CQL native transport",
		7199: "JMX monitoring",
		9160: "Thrift client",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "cassandra_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasDefaultPassword(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "cassandra_default_password",
			Message: fmt.Sprintf("service %q: Cassandra using default/weak password", svc.Name),
		})
	}

	if hasJMXExposed(envs, svc.Ports) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "cassandra_jmx_exposed",
			Message: fmt.Sprintf("service %q: JMX monitoring exposed on all interfaces", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isCassandraImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "cassandra_no_auth":
					r.Summary.NoAuth++
				case "cassandra_no_tls":
					r.Summary.NoTLS++
				case "cassandra_exposed_port":
					r.Summary.ExposedPort++
				case "cassandra_default_password":
					r.Summary.DefaultPassword++
				case "cassandra_jmx_exposed":
					r.Summary.JMXExposed++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Cassandra Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No Cassandra services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_auth=%d no_tls=%d exposed_port=%d default_password=%d jmx_exposed=%d\n",
		r.Summary.NoAuth, r.Summary.NoTLS, r.Summary.ExposedPort,
		r.Summary.DefaultPassword, r.Summary.JMXExposed)

	return b.String()
}
