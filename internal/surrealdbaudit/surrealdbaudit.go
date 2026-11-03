package surrealdbaudit

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
	StrictMode      int `json:"strict_mode"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var surrealdbImages = []string{
	"surrealdb/surrealdb", "surrealdb",
}

func isSurrealDBImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range surrealdbImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasAuth(envs []string, cmds []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "SURREAL_USER") ||
			strings.Contains(upper, "SURREAL_PASS") ||
			strings.Contains(upper, "SURREAL_AUTH=TRUE") {
			return true
		}
	}
	for _, c := range cmds {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "--user") || strings.Contains(lower, "--pass") ||
			strings.Contains(lower, "-u ") || strings.Contains(lower, "-p ") {
			return true
		}
	}
	return false
}

func hasDefaultPassword(envs []string) bool {
	defaults := []string{"root", "admin", "password", "changeme", "default", "test", "surrealdb"}
	passwordKeys := []string{
		"surreal_pass=",
		"surreal_root_pass=",
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

func hasTLS(envs []string, cmds []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "SURREAL_WEB_CRT") ||
			strings.Contains(upper, "SURREAL_WEB_KEY") ||
			strings.Contains(upper, "SURREAL_TLS_CERT") {
			return true
		}
	}
	for _, c := range cmds {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "--web-crt") || strings.Contains(lower, "--web-key") {
			return true
		}
	}
	return false
}

func hasStrictModeDisabled(envs []string, cmds []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "SURREAL_STRICT=FALSE") {
			return true
		}
	}
	for _, c := range cmds {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "--strict false") || strings.Contains(lower, "--no-strict") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment
	cmds := svc.Command

	if !hasAuth(envs, cmds) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "surrealdb_no_auth",
			Message: fmt.Sprintf("service %q: SurrealDB authentication not configured", svc.Name),
		})
	}

	if hasDefaultPassword(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "surrealdb_default_password",
			Message: fmt.Sprintf("service %q: SurrealDB using default/weak password", svc.Name),
		})
	}

	if !hasTLS(envs, cmds) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "surrealdb_no_tls",
			Message: fmt.Sprintf("service %q: SurrealDB running without TLS encryption", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		8000: "SurrealDB HTTP/WebSocket API",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "surrealdb_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasStrictModeDisabled(envs, cmds) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "surrealdb_strict_mode",
			Message: fmt.Sprintf("service %q: SurrealDB strict mode disabled", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isSurrealDBImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "surrealdb_no_auth":
					r.Summary.NoAuth++
				case "surrealdb_default_password":
					r.Summary.DefaultPassword++
				case "surrealdb_no_tls":
					r.Summary.NoTLS++
				case "surrealdb_exposed_port":
					r.Summary.ExposedPort++
				case "surrealdb_strict_mode":
					r.Summary.StrictMode++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("SurrealDB Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No SurrealDB services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_auth=%d default_password=%d no_tls=%d exposed_port=%d strict_mode=%d\n",
		r.Summary.NoAuth, r.Summary.DefaultPassword, r.Summary.NoTLS,
		r.Summary.ExposedPort, r.Summary.StrictMode)

	return b.String()
}
