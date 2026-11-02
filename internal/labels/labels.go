package labels

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

var securityLabels = map[string]string{
	"com.docker.compose.project":    "project identification",
	"org.opencontainers.image.source": "image provenance",
	"org.opencontainers.image.version": "version tracking",
	"org.opencontainers.image.vendor": "vendor identification",
}

var dangerousLabels = map[string]string{
	"traefik.http.routers":              "Traefik routing",
	"traefik.http.services":             "Traefik service",
	"traefik.http.middlewares":           "Traefik middleware",
	"caddy":                              "Caddy config",
	"com.centurylinklabs.watchtower.enable": "Watchtower auto-update",
}

var sensitiveValuePatterns = []string{
	"password", "secret", "token", "key", "credential",
	"api_key", "apikey", "auth",
}

type Finding struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Detail   string `json:"detail"`
}

type ServiceResult struct {
	Name     string            `json:"name"`
	File     string            `json:"file"`
	Labels   map[string]string `json:"labels,omitempty"`
	Findings []Finding         `json:"findings,omitempty"`
	Score    int               `json:"score"`
	Grade    string            `json:"grade"`
}

type Summary struct {
	TotalServices int `json:"total_services"`
	WithLabels    int `json:"with_labels"`
	WithIssues    int `json:"with_issues"`
	TotalFindings int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func Analyze(collected *collect.Collected) Report {
	var services []ServiceResult

	for _, cf := range collected.ComposeFiles {
		for i := range cf.Services {
			sr := analyzeService(&cf.Services[i], cf.Path)
			services = append(services, sr)
		}
	}

	summary := Summary{TotalServices: len(services)}
	for _, s := range services {
		if len(s.Labels) > 0 {
			summary.WithLabels++
		}
		if len(s.Findings) > 0 {
			summary.WithIssues++
		}
		summary.TotalFindings += len(s.Findings)
	}

	return Report{Services: services, Summary: summary}
}

func analyzeService(svc *compose.Service, file string) ServiceResult {
	sr := ServiceResult{
		Name:   svc.Name,
		File:   file,
		Labels: svc.Labels,
		Score:  100,
	}

	if len(svc.Labels) == 0 {
		sr.Grade = scoreToGrade(sr.Score)
		return sr
	}

	for key, val := range svc.Labels {
		lowerKey := strings.ToLower(key)
		lowerVal := strings.ToLower(val)

		for prefix, desc := range dangerousLabels {
			if strings.HasPrefix(lowerKey, prefix) {
				sr.Findings = append(sr.Findings, Finding{
					Service:  svc.Name,
					File:     file,
					Severity: "medium",
					Category: "infrastructure_label",
					Detail:   fmt.Sprintf("Label '%s' configures %s via labels; misconfig can expose services", key, desc),
				})
				sr.Score -= 10
				break
			}
		}

		if looksLikeSensitiveValue(lowerVal) {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "high",
				Category: "sensitive_label_value",
				Detail:   fmt.Sprintf("Label '%s' may contain a sensitive value in plain text", key),
			})
			sr.Score -= 25
		}

		if isWatchtowerAutoUpdate(lowerKey, lowerVal) {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "medium",
				Category: "auto_update_enabled",
				Detail:   "Watchtower auto-update enabled; unvetted images may be pulled automatically",
			})
			sr.Score -= 15
		}

		if isTraefikInsecure(lowerKey, lowerVal) {
			sr.Findings = append(sr.Findings, Finding{
				Service:  svc.Name,
				File:     file,
				Severity: "high",
				Category: "insecure_routing",
				Detail:   fmt.Sprintf("Label '%s' enables insecure HTTP routing without TLS", key),
			})
			sr.Score -= 20
		}
	}

	if sr.Score < 0 {
		sr.Score = 0
	}
	sr.Grade = scoreToGrade(sr.Score)
	return sr
}

func looksLikeSensitiveValue(val string) bool {
	if len(val) < 8 {
		return false
	}
	for _, pat := range sensitiveValuePatterns {
		if strings.Contains(val, pat) {
			return false
		}
	}
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	for _, c := range val {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '-' || c == '_' || c == '.' || c == '/' || c == ':':
			// common in paths/versions, not special
		default:
			hasSpecial = true
		}
	}
	mixed := 0
	if hasUpper {
		mixed++
	}
	if hasLower {
		mixed++
	}
	if hasDigit {
		mixed++
	}
	if hasSpecial {
		mixed++
	}
	return mixed >= 3 && len(val) >= 16
}

func isWatchtowerAutoUpdate(key, val string) bool {
	return key == "com.centurylinklabs.watchtower.enable" && (val == "true" || val == "1" || val == "yes")
}

func isTraefikInsecure(key, val string) bool {
	if strings.Contains(key, "traefik") && strings.Contains(key, "entrypoints") && val == "web" {
		return true
	}
	if strings.Contains(key, "traefik") && strings.Contains(key, "tls") && val == "false" {
		return true
	}
	return false
}

func scoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Label Security Audit (%d services, %d with labels, %d with issues)\n\n",
		r.Summary.TotalServices, r.Summary.WithLabels, r.Summary.WithIssues)

	for _, s := range r.Services {
		if len(s.Findings) == 0 && len(s.Labels) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %-30s [%s] score=%d\n", s.Name, s.Grade, s.Score)
		if len(s.Labels) > 0 {
			fmt.Fprintf(&b, "    labels: %d defined\n", len(s.Labels))
		}
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.Category, f.Detail)
		}
		b.WriteString("\n")
	}
	return b.String()
}
