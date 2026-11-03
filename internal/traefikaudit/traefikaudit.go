package traefikaudit

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
	DashboardExposed  int `json:"dashboard_exposed"`
	InsecureAPI       int `json:"insecure_api"`
	NoTLS             int `json:"no_tls"`
	ExposedPort       int `json:"exposed_port"`
	DebugEnabled      int `json:"debug_enabled"`
	DefaultCert       int `json:"default_cert"`
	InsecureBackend   int `json:"insecure_backend"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var traefikImages = []string{
	"traefik", "traefik/traefik", "library/traefik",
	"containous/traefik",
}

func isTraefikImage(image string) bool {
	img := strings.ToLower(image)
	for _, ti := range traefikImages {
		if strings.Contains(img, ti) {
			return true
		}
	}
	return false
}

func hasDashboardExposed(cmds, envs []string) bool {
	all := append(cmds, envs...)
	for _, s := range all {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "api.dashboard=true") || strings.Contains(lower, "api.insecure=true") {
			return true
		}
	}
	return false
}

func hasInsecureAPI(cmds, envs []string) bool {
	all := append(cmds, envs...)
	for _, s := range all {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "api.insecure=true") {
			return true
		}
	}
	return false
}

func hasNoTLS(cmds, envs []string) bool {
	all := append(cmds, envs...)
	for _, s := range all {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "entrypoints.web.address=:80") {
			hasTLS := false
			for _, t := range all {
				tl := strings.ToLower(t)
				if strings.Contains(tl, "entrypoints.websecure") || strings.Contains(tl, "tls") {
					hasTLS = true
					break
				}
			}
			if !hasTLS {
				return true
			}
		}
	}
	return false
}

func hasDebugEnabled(cmds, envs []string) bool {
	all := append(cmds, envs...)
	for _, s := range all {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "log.level=debug") || strings.Contains(lower, "accesslog=true") {
			return true
		}
	}
	return false
}

func hasDefaultCert(cmds, envs []string) bool {
	all := append(cmds, envs...)
	for _, s := range all {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "defaultcert") && (strings.Contains(lower, "snakeoil") || strings.Contains(lower, "selfsigned") || strings.Contains(lower, "self-signed")) {
			return true
		}
	}
	return false
}

func hasInsecureBackend(cmds, envs []string) bool {
	all := append(cmds, envs...)
	for _, s := range all {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "insecureskipverify=true") || strings.Contains(lower, "serverstransport.insecureskipverify") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	cmds := svc.Command
	envs := svc.Environment

	if hasDashboardExposed(cmds, envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "traefik_dashboard_exposed",
			Message: fmt.Sprintf("service %q: Traefik dashboard exposed without authentication", svc.Name),
		})
	}

	if hasInsecureAPI(cmds, envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "traefik_insecure_api",
			Message: fmt.Sprintf("service %q: Traefik API endpoint insecure (api.insecure=true)", svc.Name),
		})
	}

	if hasNoTLS(cmds, envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "traefik_no_tls",
			Message: fmt.Sprintf("service %q: Traefik serving HTTP only without TLS entrypoint", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		80:   "HTTP entrypoint",
		443:  "HTTPS entrypoint",
		8080: "Traefik Dashboard/API",
		8443: "Traefik Dashboard (HTTPS)",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "traefik_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasDebugEnabled(cmds, envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "traefik_debug_enabled",
			Message: fmt.Sprintf("service %q: Traefik debug/access logging enabled — may leak sensitive data", svc.Name),
		})
	}

	if hasDefaultCert(cmds, envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "traefik_default_cert",
			Message: fmt.Sprintf("service %q: Traefik using self-signed/snakeoil default certificate", svc.Name),
		})
	}

	if hasInsecureBackend(cmds, envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "traefik_insecure_backend",
			Message: fmt.Sprintf("service %q: Traefik skipping TLS verification for backends", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isTraefikImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "traefik_dashboard_exposed":
					r.Summary.DashboardExposed++
				case "traefik_insecure_api":
					r.Summary.InsecureAPI++
				case "traefik_no_tls":
					r.Summary.NoTLS++
				case "traefik_exposed_port":
					r.Summary.ExposedPort++
				case "traefik_debug_enabled":
					r.Summary.DebugEnabled++
				case "traefik_default_cert":
					r.Summary.DefaultCert++
				case "traefik_insecure_backend":
					r.Summary.InsecureBackend++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Traefik Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No Traefik services found.\n")
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

	fmt.Fprintf(&b, "  Summary: dashboard=%d insecure_api=%d no_tls=%d exposed_port=%d debug=%d default_cert=%d insecure_backend=%d\n",
		r.Summary.DashboardExposed, r.Summary.InsecureAPI, r.Summary.NoTLS,
		r.Summary.ExposedPort, r.Summary.DebugEnabled, r.Summary.DefaultCert, r.Summary.InsecureBackend)

	return b.String()
}
