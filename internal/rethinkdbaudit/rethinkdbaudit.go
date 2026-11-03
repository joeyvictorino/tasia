package rethinkdbaudit

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
	WebUIExposed    int `json:"web_ui_exposed"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var rethinkdbImages = []string{
	"rethinkdb", "bitnami/rethinkdb",
}

func isRethinkDBImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range rethinkdbImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasAuth(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "RETHINKDB_PASSWORD") ||
			strings.Contains(upper, "RETHINKDB_ADMIN_PASSWORD") {
			return true
		}
	}
	return false
}

func hasDefaultPassword(envs []string) bool {
	defaults := []string{"admin", "password", "rethinkdb", "changeme", "default", "test"}
	passwordKeys := []string{
		"rethinkdb_password=",
		"rethinkdb_admin_password=",
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
		if strings.Contains(upper, "RETHINKDB_TLS_CERT") ||
			strings.Contains(upper, "RETHINKDB_TLS_KEY") ||
			strings.Contains(upper, "RETHINKDB_TLS_CA") ||
			(strings.Contains(upper, "--TLS-CERT") || strings.Contains(upper, "--TLS-KEY")) {
			return true
		}
	}
	return false
}

func hasWebUIExposed(envs []string, ports []compose.PortMapping) bool {
	for _, p := range ports {
		if p.TargetPort == 8080 && p.IsAllInterfaces() {
			if !hasAuth(envs) {
				return true
			}
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
			Rule:    "rethinkdb_no_auth",
			Message: fmt.Sprintf("service %q: RethinkDB running without authentication", svc.Name),
		})
	}

	if hasDefaultPassword(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "rethinkdb_default_password",
			Message: fmt.Sprintf("service %q: RethinkDB using default/weak password", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "rethinkdb_no_tls",
			Message: fmt.Sprintf("service %q: RethinkDB running without TLS encryption", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		28015: "RethinkDB client driver",
		29015: "RethinkDB cluster",
		8080:  "RethinkDB Web UI",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "rethinkdb_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasWebUIExposed(envs, svc.Ports) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "rethinkdb_web_ui_exposed",
			Message: fmt.Sprintf("service %q: RethinkDB Web UI exposed without authentication", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isRethinkDBImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "rethinkdb_no_auth":
					r.Summary.NoAuth++
				case "rethinkdb_default_password":
					r.Summary.DefaultPassword++
				case "rethinkdb_no_tls":
					r.Summary.NoTLS++
				case "rethinkdb_exposed_port":
					r.Summary.ExposedPort++
				case "rethinkdb_web_ui_exposed":
					r.Summary.WebUIExposed++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("RethinkDB Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No RethinkDB services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_auth=%d default_password=%d no_tls=%d exposed_port=%d web_ui_exposed=%d\n",
		r.Summary.NoAuth, r.Summary.DefaultPassword, r.Summary.NoTLS,
		r.Summary.ExposedPort, r.Summary.WebUIExposed)

	return b.String()
}
