package qdrantaudit

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
	NoAPIKey    int `json:"no_api_key"`
	NoTLS       int `json:"no_tls"`
	ExposedPort int `json:"exposed_port"`
	DebugMode   int `json:"debug_mode"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var qdrantImages = []string{
	"qdrant/qdrant", "qdrant",
}

func isQdrantImage(image string) bool {
	img := strings.ToLower(image)
	for _, qi := range qdrantImages {
		if strings.Contains(img, qi) {
			return true
		}
	}
	return false
}

func hasAPIKey(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "QDRANT__SERVICE__API_KEY") ||
			strings.Contains(upper, "QDRANT_API_KEY") {
			return true
		}
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "QDRANT__TLS__CERT") ||
			strings.Contains(upper, "QDRANT__TLS__KEY") ||
			strings.Contains(upper, "QDRANT_TLS_CERT") {
			return true
		}
	}
	return false
}

func hasDebugMode(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "qdrant__log_level=debug") ||
			strings.Contains(lower, "qdrant__log_level=trace") ||
			strings.Contains(lower, "rust_log=debug") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	if !hasAPIKey(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "qdrant_no_api_key",
			Message: fmt.Sprintf("service %q: Qdrant running without API key authentication", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "qdrant_no_tls",
			Message: fmt.Sprintf("service %q: Qdrant running without TLS encryption", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		6333: "Qdrant HTTP API",
		6334: "Qdrant gRPC API",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "qdrant_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasDebugMode(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "qdrant_debug_mode",
			Message: fmt.Sprintf("service %q: Qdrant running with debug/trace logging enabled", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isQdrantImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "qdrant_no_api_key":
					r.Summary.NoAPIKey++
				case "qdrant_no_tls":
					r.Summary.NoTLS++
				case "qdrant_exposed_port":
					r.Summary.ExposedPort++
				case "qdrant_debug_mode":
					r.Summary.DebugMode++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Qdrant Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No Qdrant services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_api_key=%d no_tls=%d exposed_port=%d debug_mode=%d\n",
		r.Summary.NoAPIKey, r.Summary.NoTLS, r.Summary.ExposedPort, r.Summary.DebugMode)

	return b.String()
}
