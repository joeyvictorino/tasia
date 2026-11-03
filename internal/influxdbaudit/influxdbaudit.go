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
	AdminExposed    int `json:"admin_exposed"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var influxdbImages = []string{
	"influxdb", "bitnami/influxdb",
}

func isInfluxDBImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range influxdbImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasAuth(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "INFLUXDB_HTTP_AUTH_ENABLED=FALSE") {
			return false
		}
		if strings.Contains(upper, "INFLUXDB_HTTP_AUTH_ENABLED=TRUE") {
			return true
		}
		if strings.Contains(upper, "DOCKER_INFLUXDB_INIT_PASSWORD") ||
			strings.Contains(upper, "DOCKER_INFLUXDB_INIT_ADMIN_TOKEN") ||
			strings.Contains(upper, "INFLUXDB_ADMIN_PASSWORD") ||
			strings.Contains(upper, "INFLUXDB_HTTP_AUTH_PASSWORD") {
			return true
		}
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "INFLUXDB_HTTP_HTTPS_ENABLED=TRUE") ||
			strings.Contains(upper, "INFLUXDB_HTTP_HTTPS_CERTIFICATE") ||
			strings.Contains(upper, "INFLUXDB_TLS_CERT") {
			return true
		}
	}
	return false
}

func hasDefaultPassword(envs []string) bool {
	defaults := []string{"admin", "password", "changeme", "default", "influxdb", "test"}
	passwordKeys := []string{
		"influxdb_http_auth_password=",
		"influxdb_admin_password=",
		"docker_influxdb_init_password=",
		"docker_influxdb_init_admin_token=",
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

func hasAdminExposed(envs []string, ports []compose.PortMapping) bool {
	authEnabled := false
	bindAll := false
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "INFLUXDB_HTTP_AUTH_ENABLED=TRUE") {
			authEnabled = true
		}
		if strings.Contains(upper, "INFLUXDB_HTTP_BIND_ADDRESS") && strings.Contains(upper, "0.0.0.0") {
			bindAll = true
		}
	}
	for _, p := range ports {
		if p.TargetPort == 8086 && p.IsAllInterfaces() {
			bindAll = true
		}
	}
	return bindAll && !authEnabled
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	if !hasAuth(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "influxdb_no_auth",
			Message: fmt.Sprintf("service %q: InfluxDB authentication disabled or not configured", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "influxdb_no_tls",
			Message: fmt.Sprintf("service %q: InfluxDB running without TLS encryption", svc.Name),
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

	if hasAdminExposed(envs, svc.Ports) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "influxdb_admin_exposed",
			Message: fmt.Sprintf("service %q: InfluxDB admin API exposed without authentication", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isInfluxDBImage(svc.Image) {
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
				case "influxdb_admin_exposed":
					r.Summary.AdminExposed++
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

	fmt.Fprintf(&b, "  Summary: no_auth=%d no_tls=%d exposed_port=%d default_password=%d admin_exposed=%d\n",
		r.Summary.NoAuth, r.Summary.NoTLS, r.Summary.ExposedPort,
		r.Summary.DefaultPassword, r.Summary.AdminExposed)

	return b.String()
}
