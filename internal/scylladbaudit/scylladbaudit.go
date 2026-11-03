package scylladbaudit

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
	DefaultPassword int `json:"default_password"`
	NoTLS           int `json:"no_tls"`
	ExposedPort     int `json:"exposed_port"`
	AuthDisabled    int `json:"auth_disabled"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var scylladbImages = []string{
	"scylladb/scylla", "scylladb/scylla-enterprise",
}

func isScyllaDBImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range scylladbImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasAuth(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "SCYLLA_AUTHENTICATOR") && !strings.Contains(upper, "ALLOWALL") {
			return true
		}
		if strings.Contains(upper, "CASSANDRA_PASSWORD") ||
			strings.Contains(upper, "SCYLLA_PASSWORD") {
			return true
		}
	}
	return false
}

func hasAuthDisabled(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "SCYLLA_AUTHENTICATOR") && strings.Contains(upper, "ALLOWALL") {
			return true
		}
	}
	return false
}

func hasDefaultPassword(envs []string) bool {
	defaults := []string{"cassandra", "admin", "password", "changeme", "default", "test", "scylla"}
	passwordKeys := []string{
		"cassandra_password=",
		"scylla_password=",
	}
	for _, e := range envs {
		lower := strings.ToLower(e)
		for _, key := range passwordKeys {
			if strings.Contains(lower, key) {
				for _, d := range defaults {
					if strings.HasSuffix(lower, "="+d) {
						return true
					}
				}
			}
		}
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "SCYLLA_SSL_CERT") ||
			strings.Contains(upper, "SCYLLA_SSL_KEY") ||
			strings.Contains(upper, "SCYLLA_CLIENT_ENCRYPTION") ||
			strings.Contains(upper, "--CLIENT-ENCRYPTION-OPTIONS") {
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
			Rule:    "scylladb_no_auth",
			Message: fmt.Sprintf("service %q: ScyllaDB running without authentication", svc.Name),
		})
	}

	if hasAuthDisabled(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "scylladb_auth_disabled",
			Message: fmt.Sprintf("service %q: ScyllaDB authenticator set to AllowAllAuthenticator", svc.Name),
		})
	}

	if hasDefaultPassword(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "scylladb_default_password",
			Message: fmt.Sprintf("service %q: ScyllaDB using default/weak password", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "scylladb_no_tls",
			Message: fmt.Sprintf("service %q: ScyllaDB running without TLS encryption", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		9042:  "ScyllaDB CQL native",
		9142:  "ScyllaDB CQL SSL",
		7000:  "ScyllaDB inter-node",
		7001:  "ScyllaDB inter-node SSL",
		7199:  "ScyllaDB JMX",
		10000: "ScyllaDB REST API",
		9180:  "ScyllaDB Prometheus",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "scylladb_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isScyllaDBImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "scylladb_no_auth":
					r.Summary.NoAuth++
				case "scylladb_default_password":
					r.Summary.DefaultPassword++
				case "scylladb_no_tls":
					r.Summary.NoTLS++
				case "scylladb_exposed_port":
					r.Summary.ExposedPort++
				case "scylladb_auth_disabled":
					r.Summary.AuthDisabled++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("ScyllaDB Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No ScyllaDB services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_auth=%d default_password=%d no_tls=%d exposed_port=%d auth_disabled=%d\n",
		r.Summary.NoAuth, r.Summary.DefaultPassword, r.Summary.NoTLS,
		r.Summary.ExposedPort, r.Summary.AuthDisabled)

	return b.String()
}
