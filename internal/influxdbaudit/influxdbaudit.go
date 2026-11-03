package influxdbaudit

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
	TokenExposed    int `json:"token_exposed"`
	DebugEnabled    int `json:"debug_enabled"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var influxImages = []string{
	"influxdb", "bitnami/influxdb", "quay.io/influxdb",
}

func isInfluxImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range influxImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasAuth(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "INFLUXDB_HTTP_AUTH_ENABLED=TRUE") ||
			strings.Contains(upper, "DOCKER_INFLUXDB_INIT_USERNAME") ||
			strings.Contains(upper, "INFLUXDB_ADMIN_USER") ||
			strings.Contains(upper, "INFLUXDB_USER") {
			return true
		}
		if strings.Contains(upper, "INFLUXDB_HTTP_AUTH_ENABLED=FALSE") {
			return false
		}
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "INFLUXDB_HTTP_HTTPS_ENABLED=TRUE") ||
			strings.Contains(upper, "INFLUXDB_TLS") ||
			strings.Contains(upper, "INFLUXDB_HTTP_HTTPS_CERTIFICATE") {
			return true
		}
	}
	return false
}

func hasDefaultPassword(envs []string) bool {
	defaults := []string{"admin", "password", "changeme", "influxdb", "root", "default"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "influxdb") && strings.Contains(lower, "password=") {
			for _, d := range defaults {
				if strings.HasSuffix(lower, "="+d) {
					return true
				}
			}
		}
	}
	return false
}

func hasWeakToken(envs []string) bool {
	weakTokens := []string{"admin", "token", "secret", "changeme", "default", "test", "dev"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "influxdb_admin_token=") || strings.Contains(lower, "docker_influxdb_init_admin_token=") {
			for _, w := range weakTokens {
				if strings.HasSuffix(lower, "="+w) {
					return true
				}
			}
		}
	}
	return false
}

func hasDebugEnabled(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "influxdb_logging_level=debug") ||
			strings.Contains(lower, "influxdb_log_level=debug") {
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
			Rule:    "influxdb_no_auth",
			Message: fmt.Sprintf("service %q: InfluxDB authentication not configured", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "influxdb_no_tls",
			Message: fmt.Sprintf("service %q: InfluxDB running without TLS", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		8086: "InfluxDB HTTP API",
		8088: "InfluxDB RPC/backup",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "influxdb_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasDefaultPassword(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "influxdb_default_password",
			Message: fmt.Sprintf("service %q: InfluxDB using default/weak password", svc.Name),
		})
	}

	if hasWeakToken(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "influxdb_token_exposed",
			Message: fmt.Sprintf("service %q: InfluxDB admin token is weak/default", svc.Name),
		})
	}

	if hasDebugEnabled(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "influxdb_debug_enabled",
			Message: fmt.Sprintf("service %q: InfluxDB debug logging enabled — may leak sensitive data", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isInfluxImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "influxdb_no_auth":
					r.Summary.NoAuth++
				case "influxdb_no_tls":
					r.Summary.NoTLS++
				case "influxdb_exposed_port":
					r.Summary.ExposedPort++
				case "influxdb_default_password":
					r.Summary.DefaultPassword++
				case "influxdb_token_exposed":
					r.Summary.TokenExposed++
				case "influxdb_debug_enabled":
					r.Summary.DebugEnabled++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("InfluxDB Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No InfluxDB services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_auth=%d no_tls=%d exposed_port=%d default_password=%d token_exposed=%d debug=%d\n",
		r.Summary.NoAuth, r.Summary.NoTLS, r.Summary.ExposedPort,
		r.Summary.DefaultPassword, r.Summary.TokenExposed, r.Summary.DebugEnabled)

	return b.String()
}
