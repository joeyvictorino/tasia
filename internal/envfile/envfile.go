package envfile

import (
	"fmt"
	"regexp"
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
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	TotalFindings    int `json:"total_findings"`
	HardcodedSecrets int `json:"hardcoded_secrets"`
	EmptyPasswords   int `json:"empty_passwords"`
	DebugEnabled     int `json:"debug_enabled"`
}

var secretKeyPatterns = regexp.MustCompile(`(?i)(PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|AUTH|CREDENTIAL|DB_PASS|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|MONGO_PASSWORD|JWT_SECRET|ENCRYPTION_KEY|SIGNING_KEY|CLIENT_SECRET)`)

var debugPatterns = map[string]string{
	"DEBUG":    "true",
	"NODE_ENV": "development",
	"FLASK_DEBUG": "1",
	"RAILS_ENV":   "development",
	"APP_DEBUG":    "true",
	"DJANGO_DEBUG": "true",
}

func isSecretKey(key string) bool {
	return secretKeyPatterns.MatchString(key)
}

func isDebugSetting(key, value string) bool {
	upper := strings.ToUpper(key)
	if upper == "DEBUG" && (value == "true" || value == "1" || value == "yes") {
		return true
	}
	for k, v := range debugPatterns {
		if strings.EqualFold(key, k) && strings.EqualFold(value, v) {
			return true
		}
	}
	return false
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := parts[1]

		if isSecretKey(key) && value != "" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "envfile_hardcoded_secret",
				Message: fmt.Sprintf("Service '%s' has hardcoded secret in environment variable '%s'; use Docker secrets or an external secret manager", svc.Name, key),
			})
		}

		if isSecretKey(key) && value == "" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "envfile_empty_password",
				Message: fmt.Sprintf("Service '%s' has empty value for secret variable '%s'; this may allow unauthenticated access", svc.Name, key),
			})
		}

		if isDebugSetting(key, value) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "envfile_debug_enabled",
				Message: fmt.Sprintf("Service '%s' has debug/development mode enabled via '%s=%s'; disable in production", svc.Name, key, value),
			})
		}
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "envfile_hardcoded_secret":
				s.HardcodedSecrets++
			case "envfile_empty_password":
				s.EmptyPasswords++
			case "envfile_debug_enabled":
				s.DebugEnabled++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Environment File Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Hardcoded secrets:    %d\n", r.Summary.HardcodedSecrets)
	fmt.Fprintf(&b, "  Empty passwords:      %d\n", r.Summary.EmptyPasswords)
	fmt.Fprintf(&b, "  Debug enabled:        %d\n", r.Summary.DebugEnabled)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s\n", sr.Service)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		if len(sr.Findings) == 0 {
			fmt.Fprintf(&b, "    (no findings)\n")
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
