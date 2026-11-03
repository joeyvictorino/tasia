package minioaudit

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
	NoTLS              int `json:"no_tls"`
	ExposedPort        int `json:"exposed_port"`
	RootCredentials    int `json:"root_credentials"`
	BrowserExposed     int `json:"browser_exposed"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var minioImages = []string{
	"minio/minio", "minio/mc", "bitnami/minio",
	"quay.io/minio/minio",
}

func isMinioImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range minioImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasDefaultCredentials(envs []string) bool {
	defaults := []string{"minioadmin", "minio", "admin", "password", "changeme", "default", "minio123"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "minio_access_key=") ||
			strings.Contains(lower, "minio_root_user=") {
			for _, d := range defaults {
				if strings.HasSuffix(lower, "="+d) {
					return true
				}
			}
		}
		if strings.Contains(lower, "minio_secret_key=") ||
			strings.Contains(lower, "minio_root_password=") {
			for _, d := range defaults {
				if strings.HasSuffix(lower, "="+d) {
					return true
				}
			}
		}
	}
	return false
}

func hasTLS(envs []string, command []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "MINIO_CERTS_DIR") ||
			strings.Contains(upper, "MINIO_SERVER_URL") && strings.Contains(upper, "HTTPS") {
			return true
		}
	}
	for _, c := range command {
		if strings.Contains(c, "--certs-dir") || strings.Contains(c, "https://") {
			return true
		}
	}
	return false
}

func hasRootCredentials(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "minio_root_user=root") ||
			strings.Contains(lower, "minio_access_key=root") {
			return true
		}
	}
	return false
}

func hasBrowserExposed(envs []string, ports []compose.PortMapping) bool {
	for _, p := range ports {
		if p.TargetPort == 9001 && p.IsAllInterfaces() {
			for _, e := range envs {
				upper := strings.ToUpper(e)
				if strings.Contains(upper, "MINIO_BROWSER=OFF") {
					return false
				}
			}
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
			Rule:    "minio_default_credentials",
			Message: fmt.Sprintf("service %q: MinIO using default access key or secret key", svc.Name),
		})
	}

	if !hasTLS(envs, svc.Command) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "minio_no_tls",
			Message: fmt.Sprintf("service %q: MinIO running without TLS encryption", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		9000: "MinIO API",
		9001: "MinIO Console",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "minio_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasRootCredentials(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "minio_root_credentials",
			Message: fmt.Sprintf("service %q: MinIO using root as access key username", svc.Name),
		})
	}

	if hasBrowserExposed(envs, svc.Ports) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "minio_browser_exposed",
			Message: fmt.Sprintf("service %q: MinIO console exposed on all interfaces", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isMinioImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "minio_default_credentials":
					r.Summary.DefaultCredentials++
				case "minio_no_tls":
					r.Summary.NoTLS++
				case "minio_exposed_port":
					r.Summary.ExposedPort++
				case "minio_root_credentials":
					r.Summary.RootCredentials++
				case "minio_browser_exposed":
					r.Summary.BrowserExposed++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("MinIO Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No MinIO services found.\n")
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

	fmt.Fprintf(&b, "  Summary: default_credentials=%d no_tls=%d exposed_port=%d root_credentials=%d browser_exposed=%d\n",
		r.Summary.DefaultCredentials, r.Summary.NoTLS, r.Summary.ExposedPort,
		r.Summary.RootCredentials, r.Summary.BrowserExposed)

	return b.String()
}
