package clickhouseaudit

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service  string `json:"service"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type ServiceResult struct {
	Name     string    `json:"name"`
	Image    string    `json:"image"`
	Findings []Finding `json:"findings"`
}

type Summary struct {
	NoAuth          int `json:"no_auth"`
	DefaultPassword int `json:"default_password"`
	ExposedPort     int `json:"exposed_port"`
	NoTLS           int `json:"no_tls"`
	DebugEnabled    int `json:"debug_enabled"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func isClickhouseImage(img string) bool {
	lower := strings.ToLower(img)
	return strings.Contains(lower, "clickhouse") ||
		strings.Contains(lower, "yandex/clickhouse")
}

func hasNoAuth(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.HasPrefix(lower, "clickhouse_password=") && len(strings.SplitN(e, "=", 2)[1]) > 0 {
			return false
		}
		if strings.Contains(lower, "clickhouse_default_access_management=1") {
			return false
		}
	}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.HasPrefix(lower, "clickhouse_password=") || strings.Contains(lower, "clickhouse_default_access_management") {
			return false
		}
	}
	return true
}

func hasDefaultPassword(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.HasPrefix(lower, "clickhouse_password=") {
			val := strings.SplitN(e, "=", 2)[1]
			v := strings.ToLower(val)
			return v == "" || v == "default" || v == "clickhouse" || v == "password"
		}
	}
	return false
}

func hasNoTLS(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "clickhouse_ssl=false") ||
			strings.Contains(lower, "clickhouse_tls=false") ||
			strings.Contains(lower, "disable_ssl=true") {
			return true
		}
	}
	return false
}

func hasDebugEnabled(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "clickhouse_log_level=trace") ||
			strings.Contains(lower, "clickhouse_log_level=debug") ||
			strings.Contains(lower, "log_level=trace") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Name: svc.Name, Image: svc.Image}

	if hasNoAuth(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			Rule:     "clickhouse_no_auth",
			Severity: "high",
			Message:  "ClickHouse has no authentication configured",
		})
	}

	if hasDefaultPassword(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			Rule:     "clickhouse_default_password",
			Severity: "high",
			Message:  "ClickHouse uses default or empty password",
		})
	}

	if hasNoTLS(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			Rule:     "clickhouse_no_tls",
			Severity: "medium",
			Message:  "ClickHouse TLS/SSL is explicitly disabled",
		})
	}

	if hasDebugEnabled(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			Rule:     "clickhouse_debug_enabled",
			Severity: "low",
			Message:  "ClickHouse debug/trace logging enabled in production",
		})
	}

	exposedPorts := map[int]string{
		8123: "HTTP interface",
		9000: "native protocol",
		9009: "interserver",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok && p.IsAllInterfaces() {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				Rule:     "clickhouse_exposed_port",
				Severity: "medium",
				Message:  fmt.Sprintf("ClickHouse %s port %d exposed on all interfaces", desc, p.TargetPort),
			})
		}
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isClickhouseImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "clickhouse_no_auth":
					r.Summary.NoAuth++
				case "clickhouse_default_password":
					r.Summary.DefaultPassword++
				case "clickhouse_exposed_port":
					r.Summary.ExposedPort++
				case "clickhouse_no_tls":
					r.Summary.NoTLS++
				case "clickhouse_debug_enabled":
					r.Summary.DebugEnabled++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ClickHouse Security Audit: %s\n", r.Path)
	b.WriteString(strings.Repeat("=", 50) + "\n\n")

	if len(r.Services) == 0 {
		b.WriteString("  No ClickHouse services found.\n")
		return b.String()
	}

	for _, svc := range r.Services {
		fmt.Fprintf(&b, "  Service: %s (%s)\n", svc.Name, svc.Image)
		if len(svc.Findings) == 0 {
			b.WriteString("    No issues found.\n")
		}
		for _, f := range svc.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.Rule, f.Message)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "  Summary: auth=%d default_pass=%d exposed=%d no_tls=%d debug=%d\n",
		r.Summary.NoAuth, r.Summary.DefaultPassword, r.Summary.ExposedPort,
		r.Summary.NoTLS, r.Summary.DebugEnabled)

	return b.String()
}
