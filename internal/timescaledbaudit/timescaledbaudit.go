package timescaledbaudit

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
	TrustAuth       int `json:"trust_auth"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var timescaleImages = []string{
	"timescale/timescaledb", "timescaledb",
}

func isTimescaleDBImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range timescaleImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasAuth(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "POSTGRES_PASSWORD") ||
			strings.Contains(upper, "POSTGRES_PASSWORD_FILE") {
			return true
		}
	}
	return false
}

func hasDefaultPassword(envs []string) bool {
	defaults := []string{"postgres", "admin", "password", "changeme", "default", "test", "timescaledb"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.HasPrefix(lower, "postgres_password=") {
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
		if strings.Contains(upper, "POSTGRES_SSL=ON") ||
			strings.Contains(upper, "POSTGRES_SSL_CERT") ||
			strings.Contains(upper, "SSL_CERT_FILE") ||
			strings.Contains(upper, "PGSSLMODE=VERIFY") ||
			strings.Contains(upper, "PGSSLMODE=REQUIRE") {
			return true
		}
	}
	return false
}

func hasTrustAuth(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "POSTGRES_HOST_AUTH_METHOD=TRUST") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	trustAuth := hasTrustAuth(envs)

	if !hasAuth(envs) && !trustAuth {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "timescaledb_no_auth",
			Message: fmt.Sprintf("service %q: TimescaleDB has no password configured", svc.Name),
		})
	}

	if trustAuth {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "timescaledb_trust_auth",
			Message: fmt.Sprintf("service %q: TimescaleDB using trust authentication (no password required)", svc.Name),
		})
	}

	if hasDefaultPassword(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "timescaledb_default_password",
			Message: fmt.Sprintf("service %q: TimescaleDB using default/weak password", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "timescaledb_no_tls",
			Message: fmt.Sprintf("service %q: TimescaleDB running without TLS encryption", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		5432: "TimescaleDB/PostgreSQL",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "timescaledb_exposed_port",
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
			if !isTimescaleDBImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "timescaledb_no_auth":
					r.Summary.NoAuth++
				case "timescaledb_default_password":
					r.Summary.DefaultPassword++
				case "timescaledb_no_tls":
					r.Summary.NoTLS++
				case "timescaledb_exposed_port":
					r.Summary.ExposedPort++
				case "timescaledb_trust_auth":
					r.Summary.TrustAuth++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("TimescaleDB Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No TimescaleDB services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_auth=%d default_password=%d no_tls=%d exposed_port=%d trust_auth=%d\n",
		r.Summary.NoAuth, r.Summary.DefaultPassword, r.Summary.NoTLS,
		r.Summary.ExposedPort, r.Summary.TrustAuth)

	return b.String()
}
