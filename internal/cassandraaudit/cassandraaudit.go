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
	NoAuth       int `json:"no_auth"`
	NoTLS        int `json:"no_tls"`
	NoEncryption int `json:"no_encryption"`
	ExposedPort  int `json:"exposed_port"`
	DefaultPassword int `json:"default_password"`
	JMXEnabled   int `json:"jmx_enabled"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var cassandraImages = []string{
	"cassandra", "bitnami/cassandra", "datastax/dse-server",
	"scylladb/scylla", "datastax/cassandra",
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
		if strings.Contains(upper, "CASSANDRA_AUTHENTICATOR") && !strings.Contains(upper, "ALLOWALL") {
			return true
		}
		if strings.Contains(upper, "CASSANDRA_PASSWORD") ||
			strings.Contains(upper, "CASSANDRA_AUTH_ENABLED=TRUE") {
			return true
		}
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "CLIENT_ENCRYPTION_ENABLED=TRUE") ||
			strings.Contains(upper, "NATIVE_TRANSPORT_PORT_SSL") ||
			strings.Contains(upper, "CLIENT_ENCRYPTION_OPTIONS") && strings.Contains(upper, "ENABLED=TRUE") ||
			strings.Contains(upper, "SSL_STORAGE_PORT") {
			return true
		}
	}
	return false
}

func hasInternodeEncryption(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "INTERNODE_ENCRYPTION=ALL") ||
			strings.Contains(upper, "INTERNODE_ENCRYPTION=DC") ||
			strings.Contains(upper, "INTERNODE_ENCRYPTION=RACK") ||
			strings.Contains(upper, "SERVER_ENCRYPTION_ENABLED=TRUE") {
			return true
		}
	}
	return false
}

func hasDefaultPassword(envs []string) bool {
	defaults := []string{"cassandra", "admin", "password", "changeme", "default"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "cassandra_password=") || strings.Contains(lower, "password=") {
			for _, d := range defaults {
				if strings.HasSuffix(lower, "="+d) {
					return true
				}
			}
		}
	}
	return false
}

func hasJMXExposed(envs []string, ports []compose.PortMapping) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "JMX_PORT") ||
			strings.Contains(upper, "JMX_REMOTE_AUTHENTICATE=FALSE") {
			return true
		}
	}
	for _, p := range ports {
		if p.TargetPort == 7199 && p.IsAllInterfaces() {
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
			Level:   "high",
			Rule:    "cassandra_no_auth",
			Message: fmt.Sprintf("service %q: Cassandra has no authentication configured", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "cassandra_no_tls",
			Message: fmt.Sprintf("service %q: Cassandra running without TLS for client connections", svc.Name),
		})
	}

	if !hasInternodeEncryption(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cassandra_no_internode_encryption",
			Message: fmt.Sprintf("service %q: Cassandra internode encryption not configured", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		9042: "Cassandra native transport (CQL)",
		9160: "Cassandra Thrift (legacy)",
		7000: "Cassandra internode cluster",
		7001: "Cassandra internode SSL",
		7199: "Cassandra JMX",
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
			Level:   "high",
			Rule:    "cassandra_jmx_exposed",
			Message: fmt.Sprintf("service %q: Cassandra JMX exposed or unauthenticated", svc.Name),
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
				case "cassandra_no_internode_encryption":
					r.Summary.NoEncryption++
				case "cassandra_exposed_port":
					r.Summary.ExposedPort++
				case "cassandra_default_password":
					r.Summary.DefaultPassword++
				case "cassandra_jmx_exposed":
					r.Summary.JMXEnabled++
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

	fmt.Fprintf(&b, "  Summary: no_auth=%d no_tls=%d no_encryption=%d exposed_port=%d default_password=%d jmx_enabled=%d\n",
		r.Summary.NoAuth, r.Summary.NoTLS, r.Summary.NoEncryption,
		r.Summary.ExposedPort, r.Summary.DefaultPassword, r.Summary.JMXEnabled)

	return b.String()
}
