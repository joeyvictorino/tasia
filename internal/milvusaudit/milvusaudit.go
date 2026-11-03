package milvusaudit

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
	RootUser        int `json:"root_user"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var milvusImages = []string{
	"milvusdb/milvus", "milvus", "bitnami/milvus",
}

func isMilvusImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range milvusImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasAuth(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "MILVUS_AUTH_ENABLED=TRUE") ||
			strings.Contains(upper, "COMMON_SECURITY_AUTHORIZATIONENABLED=TRUE") ||
			strings.Contains(upper, "MILVUS_TOKEN") ||
			strings.Contains(upper, "MILVUS_ROOT_PASSWORD") {
			return true
		}
	}
	return false
}

func hasDefaultPassword(envs []string) bool {
	defaults := []string{"milvus", "admin", "password", "changeme", "default", "test", "root"}
	passwordKeys := []string{
		"milvus_root_password=",
		"milvus_token=",
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
		if strings.Contains(upper, "MILVUS_TLS_ENABLED=TRUE") ||
			strings.Contains(upper, "TLS_CERT_FILE") ||
			strings.Contains(upper, "COMMON_SECURITY_TLSMODE") {
			return true
		}
	}
	return false
}

func hasRootUser(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "milvus_root_password=") {
			return false
		}
	}
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "MILVUS_AUTH_ENABLED=TRUE") ||
			strings.Contains(upper, "COMMON_SECURITY_AUTHORIZATIONENABLED=TRUE") {
			return false
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
			Rule:    "milvus_no_auth",
			Message: fmt.Sprintf("service %q: Milvus authentication not enabled", svc.Name),
		})
	}

	if hasDefaultPassword(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "milvus_default_password",
			Message: fmt.Sprintf("service %q: Milvus using default/weak password", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "milvus_no_tls",
			Message: fmt.Sprintf("service %q: Milvus running without TLS encryption", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		19530: "Milvus gRPC API",
		9091:  "Milvus metrics",
		19121: "Milvus HTTP API",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "milvus_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasRootUser(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "milvus_root_user",
			Message: fmt.Sprintf("service %q: Milvus root user has no custom password", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isMilvusImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "milvus_no_auth":
					r.Summary.NoAuth++
				case "milvus_default_password":
					r.Summary.DefaultPassword++
				case "milvus_no_tls":
					r.Summary.NoTLS++
				case "milvus_exposed_port":
					r.Summary.ExposedPort++
				case "milvus_root_user":
					r.Summary.RootUser++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Milvus Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No Milvus services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_auth=%d default_password=%d no_tls=%d exposed_port=%d root_user=%d\n",
		r.Summary.NoAuth, r.Summary.DefaultPassword, r.Summary.NoTLS,
		r.Summary.ExposedPort, r.Summary.RootUser)

	return b.String()
}
