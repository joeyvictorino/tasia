package couchdbaudit

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
	AdminParty      int `json:"admin_party"`
	DefaultPassword int `json:"default_password"`
	NoTLS           int `json:"no_tls"`
	ExposedPort     int `json:"exposed_port"`
	CORSOpen        int `json:"cors_open"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var couchdbImages = []string{
	"couchdb", "bitnami/couchdb", "apache/couchdb",
}

func isCouchDBImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range couchdbImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasAdminParty(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "COUCHDB_USER") || strings.Contains(upper, "COUCHDB_PASSWORD") {
			return false
		}
	}
	return true
}

func hasDefaultPassword(envs []string) bool {
	defaults := []string{"admin", "password", "couchdb", "changeme", "default", "test"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.HasPrefix(lower, "couchdb_password=") {
			for _, d := range defaults {
				if strings.HasSuffix(lower, "="+d) {
					return true
				}
			}
		}
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "COUCHDB_CERTFILE") ||
			strings.Contains(upper, "COUCHDB_KEYFILE") ||
			strings.Contains(upper, "SSL_CERT_FILE") ||
			strings.Contains(upper, "COUCHDB_HTTPS_ENABLE=TRUE") {
			return true
		}
	}
	return false
}

func hasCORSOpen(envs []string) bool {
	corsEnabled := false
	originStar := false
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "couchdb_cors_enable=true") || strings.Contains(lower, "cors_enable=true") {
			corsEnabled = true
		}
		if strings.Contains(lower, "couchdb_cors_origins=*") || strings.Contains(lower, "cors_origins=*") {
			originStar = true
		}
	}
	return corsEnabled && originStar
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	if hasAdminParty(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "couchdb_admin_party",
			Message: fmt.Sprintf("service %q: CouchDB running in admin party mode (no admin credentials)", svc.Name),
		})
	}

	if hasDefaultPassword(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "couchdb_default_password",
			Message: fmt.Sprintf("service %q: CouchDB using default/weak password", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "couchdb_no_tls",
			Message: fmt.Sprintf("service %q: CouchDB running without TLS encryption", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		5984:  "CouchDB HTTP API",
		6984:  "CouchDB HTTPS API",
		4369:  "CouchDB Erlang EPMD",
		9100:  "CouchDB Erlang distribution",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "couchdb_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasCORSOpen(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "couchdb_cors_open",
			Message: fmt.Sprintf("service %q: CouchDB CORS enabled with wildcard origin", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isCouchDBImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "couchdb_admin_party":
					r.Summary.AdminParty++
				case "couchdb_default_password":
					r.Summary.DefaultPassword++
				case "couchdb_no_tls":
					r.Summary.NoTLS++
				case "couchdb_exposed_port":
					r.Summary.ExposedPort++
				case "couchdb_cors_open":
					r.Summary.CORSOpen++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("CouchDB Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No CouchDB services found.\n")
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

	fmt.Fprintf(&b, "  Summary: admin_party=%d default_password=%d no_tls=%d exposed_port=%d cors_open=%d\n",
		r.Summary.AdminParty, r.Summary.DefaultPassword, r.Summary.NoTLS,
		r.Summary.ExposedPort, r.Summary.CORSOpen)

	return b.String()
}
