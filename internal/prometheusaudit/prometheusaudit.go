package prometheusaudit

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
	ExposedPort     int `json:"exposed_port"`
	AdminEnabled    int `json:"admin_enabled"`
	RemoteWrite     int `json:"remote_write"`
	DebugEnabled    int `json:"debug_enabled"`
	RetentionLarge  int `json:"retention_large"`
	LifecycleAPI    int `json:"lifecycle_api"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var prometheusImages = []string{
	"prom/prometheus", "quay.io/prometheus/prometheus",
	"bitnami/prometheus", "prometheuscommunity/prometheus",
}

func isPrometheusImage(image string) bool {
	img := strings.ToLower(image)
	for _, pi := range prometheusImages {
		if strings.Contains(img, pi) {
			return true
		}
	}
	return false
}

func hasNoAuth(envs []string, cmds []string) bool {
	for _, c := range cmds {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "--web.enable-admin-api") ||
			strings.Contains(lower, "--web.enable-lifecycle") {
			return true
		}
	}
	return true
}

func hasAdminEnabled(cmds []string) bool {
	for _, c := range cmds {
		if strings.Contains(strings.ToLower(c), "--web.enable-admin-api") {
			return true
		}
	}
	return false
}

func hasLifecycleAPI(cmds []string) bool {
	for _, c := range cmds {
		if strings.Contains(strings.ToLower(c), "--web.enable-lifecycle") {
			return true
		}
	}
	return false
}

func hasRemoteWrite(envs []string, cmds []string) bool {
	for _, c := range cmds {
		if strings.Contains(strings.ToLower(c), "--web.enable-remote-write-receiver") {
			return true
		}
	}
	for _, e := range envs {
		if strings.Contains(strings.ToLower(e), "remote_write") {
			return true
		}
	}
	return false
}

func hasDebugEnabled(envs []string, cmds []string) bool {
	for _, c := range cmds {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "--log.level=debug") {
			return true
		}
	}
	return false
}

func hasLargeRetention(cmds []string) bool {
	for _, c := range cmds {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "--storage.tsdb.retention.time=") {
			parts := strings.SplitAfter(lower, "retention.time=")
			if len(parts) > 1 {
				val := strings.TrimSpace(parts[1])
				if strings.Contains(val, "y") || strings.Contains(val, "365d") {
					return true
				}
			}
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment
	cmds := svc.Command

	if hasAdminEnabled(cmds) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "prometheus_admin_api",
			Message: fmt.Sprintf("service %q: Prometheus admin API enabled — allows TSDB deletion", svc.Name),
		})
	}

	if hasLifecycleAPI(cmds) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "prometheus_lifecycle_api",
			Message: fmt.Sprintf("service %q: Prometheus lifecycle API enabled — allows remote reload/shutdown", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		9090: "Prometheus HTTP",
		9091: "Pushgateway",
		9093: "Alertmanager",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "prometheus_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasRemoteWrite(envs, cmds) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "prometheus_remote_write",
			Message: fmt.Sprintf("service %q: remote write receiver enabled — verify authentication", svc.Name),
		})
	}

	if hasDebugEnabled(envs, cmds) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "prometheus_debug_enabled",
			Message: fmt.Sprintf("service %q: Prometheus debug logging enabled", svc.Name),
		})
	}

	if hasLargeRetention(cmds) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "prometheus_retention_large",
			Message: fmt.Sprintf("service %q: Prometheus has very large retention period", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isPrometheusImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "prometheus_no_auth":
					r.Summary.NoAuth++
				case "prometheus_exposed_port":
					r.Summary.ExposedPort++
				case "prometheus_admin_api":
					r.Summary.AdminEnabled++
				case "prometheus_remote_write":
					r.Summary.RemoteWrite++
				case "prometheus_debug_enabled":
					r.Summary.DebugEnabled++
				case "prometheus_retention_large":
					r.Summary.RetentionLarge++
				case "prometheus_lifecycle_api":
					r.Summary.LifecycleAPI++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Prometheus Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No Prometheus services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_auth=%d exposed=%d admin=%d remote_write=%d debug=%d retention=%d lifecycle=%d\n",
		r.Summary.NoAuth, r.Summary.ExposedPort, r.Summary.AdminEnabled,
		r.Summary.RemoteWrite, r.Summary.DebugEnabled, r.Summary.RetentionLarge, r.Summary.LifecycleAPI)

	return b.String()
}
