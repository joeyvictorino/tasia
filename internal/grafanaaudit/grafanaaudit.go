package grafanaaudit

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
	AnonAccess         int `json:"anon_access"`
	NoTLS              int `json:"no_tls"`
	ExposedPort        int `json:"exposed_port"`
	DebugEnabled       int `json:"debug_enabled"`
	DisabledAuth       int `json:"disabled_auth"`
	AlertingExposed    int `json:"alerting_exposed"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var grafanaImages = []string{
	"grafana/grafana", "grafana/grafana-oss", "grafana/grafana-enterprise",
	"bitnami/grafana",
}

func isGrafanaImage(image string) bool {
	img := strings.ToLower(image)
	for _, gi := range grafanaImages {
		if strings.Contains(img, gi) {
			return true
		}
	}
	return false
}

func hasDefaultCredentials(envs []string) bool {
	defaults := []string{"admin", "grafana", "password", "changeme", "default"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "gf_security_admin_password=") {
			for _, d := range defaults {
				if strings.Contains(lower, "password="+d) {
					return true
				}
			}
		}
	}
	return false
}

func hasAnonAccess(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "gf_auth_anonymous_enabled=true") {
			return true
		}
	}
	return false
}

func hasDisabledAuth(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "gf_auth_disable_login_form=true") ||
			strings.Contains(lower, "gf_auth_basic_enabled=false") {
			return true
		}
	}
	return false
}

func hasNoTLS(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "gf_server_protocol=http") {
			return true
		}
	}
	return true
}

func hasDebugEnabled(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "gf_log_level=debug") {
			return true
		}
	}
	return false
}

func hasAlertingExposed(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "gf_unified_alerting_enabled=true") ||
			strings.Contains(lower, "gf_alerting_enabled=true") {
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
			Rule:    "grafana_default_credentials",
			Message: fmt.Sprintf("service %q: Grafana uses default/weak admin password", svc.Name),
		})
	}

	if hasAnonAccess(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "grafana_anon_access",
			Message: fmt.Sprintf("service %q: Grafana anonymous access enabled", svc.Name),
		})
	}

	if hasDisabledAuth(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "grafana_disabled_auth",
			Message: fmt.Sprintf("service %q: Grafana login/basic auth disabled", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		3000: "Grafana HTTP",
		3001: "Grafana HTTP (alt)",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "grafana_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasDebugEnabled(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "grafana_debug_enabled",
			Message: fmt.Sprintf("service %q: Grafana debug logging enabled", svc.Name),
		})
	}

	if hasAlertingExposed(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "grafana_alerting_exposed",
			Message: fmt.Sprintf("service %q: Grafana alerting enabled — verify notification channels are secured", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isGrafanaImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "grafana_default_credentials":
					r.Summary.DefaultCredentials++
				case "grafana_anon_access":
					r.Summary.AnonAccess++
				case "grafana_no_tls":
					r.Summary.NoTLS++
				case "grafana_exposed_port":
					r.Summary.ExposedPort++
				case "grafana_debug_enabled":
					r.Summary.DebugEnabled++
				case "grafana_disabled_auth":
					r.Summary.DisabledAuth++
				case "grafana_alerting_exposed":
					r.Summary.AlertingExposed++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Grafana Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No Grafana services found.\n")
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

	fmt.Fprintf(&b, "  Summary: default_creds=%d anon=%d no_tls=%d exposed=%d debug=%d disabled_auth=%d alerting=%d\n",
		r.Summary.DefaultCredentials, r.Summary.AnonAccess, r.Summary.NoTLS,
		r.Summary.ExposedPort, r.Summary.DebugEnabled, r.Summary.DisabledAuth, r.Summary.AlertingExposed)

	return b.String()
}
