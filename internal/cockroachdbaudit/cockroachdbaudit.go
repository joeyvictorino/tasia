package cockroachdbaudit

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
	Insecure        int `json:"insecure"`
	NoTLS           int `json:"no_tls"`
	ExposedPort     int `json:"exposed_port"`
	DefaultCerts    int `json:"default_certs"`
	UIExposed       int `json:"ui_exposed"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var cockroachImages = []string{
	"cockroachdb/cockroach", "cockroach",
}

func isCockroachImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range cockroachImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func isInsecure(envs []string, command []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "COCKROACH_INSECURE=TRUE") {
			return true
		}
	}
	for _, c := range command {
		if strings.Contains(c, "--insecure") {
			return true
		}
	}
	return false
}

func hasTLS(envs []string, command []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "COCKROACH_CERTS_DIR") ||
			strings.Contains(upper, "SSL_CERT") ||
			strings.Contains(upper, "TLS_CERT") {
			return true
		}
	}
	for _, c := range command {
		if strings.Contains(c, "--certs-dir") {
			return true
		}
	}
	return false
}

func hasDefaultCerts(envs []string) bool {
	defaults := []string{"/cockroach/cockroach-certs", "/certs", "/cockroach-certs"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "cockroach_certs_dir=") {
			for _, d := range defaults {
				if strings.HasSuffix(lower, "="+d) {
					return true
				}
			}
		}
	}
	return false
}

func hasUIExposed(envs []string, ports []compose.PortMapping) bool {
	for _, p := range ports {
		if p.TargetPort == 8080 && p.IsAllInterfaces() {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	if isInsecure(envs, svc.Command) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "cockroachdb_insecure",
			Message: fmt.Sprintf("service %q: CockroachDB running in insecure mode", svc.Name),
		})
	}

	if !hasTLS(envs, svc.Command) && !isInsecure(envs, svc.Command) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "cockroachdb_no_tls",
			Message: fmt.Sprintf("service %q: CockroachDB running without TLS configuration", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		26257: "CockroachDB SQL",
		8080:  "CockroachDB Admin UI",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "cockroachdb_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasDefaultCerts(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "cockroachdb_default_certs",
			Message: fmt.Sprintf("service %q: CockroachDB using default certificate directory", svc.Name),
		})
	}

	if hasUIExposed(envs, svc.Ports) {
		insecureOrNoAuth := isInsecure(envs, svc.Command)
		if insecureOrNoAuth {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "cockroachdb_ui_exposed",
				Message: fmt.Sprintf("service %q: CockroachDB Admin UI exposed on all interfaces in insecure mode", svc.Name),
			})
		}
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isCockroachImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "cockroachdb_insecure":
					r.Summary.Insecure++
				case "cockroachdb_no_tls":
					r.Summary.NoTLS++
				case "cockroachdb_exposed_port":
					r.Summary.ExposedPort++
				case "cockroachdb_default_certs":
					r.Summary.DefaultCerts++
				case "cockroachdb_ui_exposed":
					r.Summary.UIExposed++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("CockroachDB Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No CockroachDB services found.\n")
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

	fmt.Fprintf(&b, "  Summary: insecure=%d no_tls=%d exposed_port=%d default_certs=%d ui_exposed=%d\n",
		r.Summary.Insecure, r.Summary.NoTLS, r.Summary.ExposedPort,
		r.Summary.DefaultCerts, r.Summary.UIExposed)

	return b.String()
}
