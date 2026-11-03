package envscan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type Finding struct {
	File     string `json:"file"`
	Service  string `json:"service"`
	Variable string `json:"variable"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Message  string `json:"message"`
	Line     int    `json:"line,omitempty"`
}

type Summary struct {
	FilesChecked  int `json:"files_checked"`
	TotalVars     int `json:"total_vars"`
	TotalFindings int `json:"total_findings"`
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`
}

type Report struct {
	Summary  Summary   `json:"summary"`
	Findings []Finding `json:"findings"`
}

var debugKeys = map[string]bool{
	"DEBUG":             true,
	"APP_DEBUG":         true,
	"FLASK_DEBUG":       true,
	"DJANGO_DEBUG":      true,
	"NODE_DEBUG":        true,
	"RAILS_ENV":         true,
	"NODE_ENV":          true,
	"FLASK_ENV":         true,
	"LOG_LEVEL":         true,
	"LOGLEVEL":          true,
	"VERBOSE":           true,
	"TRACE":             true,
}

var debugTrueValues = map[string]bool{
	"1": true, "true": true, "yes": true, "on": true, "debug": true,
	"development": true, "trace": true, "verbose": true,
}

var secretKeyPatterns = []string{
	"PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
	"ACCESS_KEY", "PRIVATE_KEY", "AUTH_TOKEN", "CREDENTIALS",
	"DB_PASS", "MYSQL_ROOT_PASSWORD", "POSTGRES_PASSWORD",
	"REDIS_PASSWORD", "MONGO_PASSWORD", "AWS_SECRET_ACCESS_KEY",
	"GITHUB_TOKEN", "NPM_TOKEN", "STRIPE_SECRET",
}

var insecureProtocolRe = regexp.MustCompile(`^https?://`)
var httpOnlyRe = regexp.MustCompile(`^http://[^/]`)
var weakPasswordRe = regexp.MustCompile(`^(password|pass|admin|root|test|123456|changeme|secret|default|qwerty|abc123)$`)

func Analyze(c *collect.Collected) Report {
	var findings []Finding
	totalVars := 0
	filesChecked := 0

	for _, cf := range c.ComposeFiles {
		if len(cf.Services) == 0 {
			continue
		}
		filesChecked++
		for _, svc := range cf.Services {
			for _, env := range svc.Environment {
				totalVars++
				parts := strings.SplitN(env, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key := parts[0]
				val := parts[1]
				upperKey := strings.ToUpper(key)

				if f := checkDebugMode(cf.Path, svc.Name, key, val, upperKey, svc.EnvLine); f != nil {
					findings = append(findings, *f)
				}
				if f := checkInsecureProtocol(cf.Path, svc.Name, key, val, svc.EnvLine); f != nil {
					findings = append(findings, *f)
				}
				if f := checkWeakPassword(cf.Path, svc.Name, key, val, upperKey, svc.EnvLine); f != nil {
					findings = append(findings, *f)
				}
				if f := checkEmptySecret(cf.Path, svc.Name, key, val, upperKey, svc.EnvLine); f != nil {
					findings = append(findings, *f)
				}
				if f := checkTLSDisabled(cf.Path, svc.Name, key, val, upperKey, svc.EnvLine); f != nil {
					findings = append(findings, *f)
				}
				if f := checkWildcardBind(cf.Path, svc.Name, key, val, upperKey, svc.EnvLine); f != nil {
					findings = append(findings, *f)
				}
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if sevRank(findings[i].Severity) != sevRank(findings[j].Severity) {
			return sevRank(findings[i].Severity) > sevRank(findings[j].Severity)
		}
		return findings[i].Variable < findings[j].Variable
	})

	r := Report{
		Summary: Summary{
			FilesChecked:  filesChecked,
			TotalVars:     totalVars,
			TotalFindings: len(findings),
		},
		Findings: findings,
	}
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			r.Summary.CriticalCount++
		case "high":
			r.Summary.HighCount++
		case "medium":
			r.Summary.MediumCount++
		case "low":
			r.Summary.LowCount++
		}
	}
	return r
}

func checkDebugMode(file, svc, key, val, upperKey string, line int) *Finding {
	if !debugKeys[upperKey] {
		return nil
	}
	lowerVal := strings.ToLower(val)
	if !debugTrueValues[lowerVal] {
		return nil
	}
	return &Finding{
		File:     file,
		Service:  svc,
		Variable: key,
		Severity: "medium",
		Category: "debug_mode",
		Message:  fmt.Sprintf("debug/development mode enabled via %s=%s", key, val),
		Line:     line,
	}
}

func checkInsecureProtocol(file, svc, key, val string, line int) *Finding {
	if !httpOnlyRe.MatchString(val) {
		return nil
	}
	if strings.Contains(strings.ToLower(val), "localhost") || strings.Contains(val, "127.0.0.1") {
		return nil
	}
	return &Finding{
		File:     file,
		Service:  svc,
		Variable: key,
		Severity: "high",
		Category: "insecure_protocol",
		Message:  fmt.Sprintf("%s uses unencrypted HTTP for non-local endpoint", key),
		Line:     line,
	}
}

func checkWeakPassword(file, svc, key, val, upperKey string, line int) *Finding {
	isSecretKey := false
	for _, pat := range secretKeyPatterns {
		if strings.Contains(upperKey, pat) {
			isSecretKey = true
			break
		}
	}
	if !isSecretKey {
		return nil
	}
	if weakPasswordRe.MatchString(strings.ToLower(val)) {
		return &Finding{
			File:     file,
			Service:  svc,
			Variable: key,
			Severity: "critical",
			Category: "weak_password",
			Message:  fmt.Sprintf("%s contains a commonly guessed password", key),
			Line:     line,
		}
	}
	return nil
}

func checkEmptySecret(file, svc, key, val, upperKey string, line int) *Finding {
	if val != "" {
		return nil
	}
	isSecretKey := false
	for _, pat := range secretKeyPatterns {
		if strings.Contains(upperKey, pat) {
			isSecretKey = true
			break
		}
	}
	if !isSecretKey {
		return nil
	}
	return &Finding{
		File:     file,
		Service:  svc,
		Variable: key,
		Severity: "high",
		Category: "empty_secret",
		Message:  fmt.Sprintf("%s is set to an empty value", key),
		Line:     line,
	}
}

func checkTLSDisabled(file, svc, key, val, upperKey string, line int) *Finding {
	tlsDisableKeys := map[string]bool{
		"TLS_VERIFY":          true,
		"SSL_VERIFY":          true,
		"NODE_TLS_REJECT_UNAUTHORIZED": true,
		"CURL_CA_BUNDLE":      true,
		"REQUESTS_CA_BUNDLE":  true,
		"SSL_CERT_FILE":       true,
		"PYTHONHTTPSVERIFY":   true,
		"GIT_SSL_NO_VERIFY":   true,
	}
	lowerVal := strings.ToLower(val)

	if upperKey == "NODE_TLS_REJECT_UNAUTHORIZED" && val == "0" {
		return &Finding{
			File: file, Service: svc, Variable: key,
			Severity: "critical", Category: "tls_disabled",
			Message: "TLS certificate verification disabled via NODE_TLS_REJECT_UNAUTHORIZED=0",
			Line: line,
		}
	}
	if upperKey == "PYTHONHTTPSVERIFY" && val == "0" {
		return &Finding{
			File: file, Service: svc, Variable: key,
			Severity: "critical", Category: "tls_disabled",
			Message: "HTTPS verification disabled via PYTHONHTTPSVERIFY=0",
			Line: line,
		}
	}
	if upperKey == "GIT_SSL_NO_VERIFY" && (lowerVal == "1" || lowerVal == "true") {
		return &Finding{
			File: file, Service: svc, Variable: key,
			Severity: "high", Category: "tls_disabled",
			Message: "Git SSL verification disabled",
			Line: line,
		}
	}
	if tlsDisableKeys[upperKey] && (lowerVal == "false" || lowerVal == "0" || lowerVal == "no") {
		if upperKey == "TLS_VERIFY" || upperKey == "SSL_VERIFY" {
			return &Finding{
				File: file, Service: svc, Variable: key,
				Severity: "high", Category: "tls_disabled",
				Message: fmt.Sprintf("TLS/SSL verification disabled via %s=%s", key, val),
				Line: line,
			}
		}
	}
	return nil
}

func checkWildcardBind(file, svc, key, val, upperKey string, line int) *Finding {
	bindKeys := map[string]bool{
		"BIND_ADDRESS": true, "BIND_ADDR": true, "HOST": true,
		"LISTEN_ADDR": true, "SERVER_HOST": true, "LISTEN_ADDRESS": true,
	}
	if !bindKeys[upperKey] {
		return nil
	}
	if val == "0.0.0.0" || val == "::" {
		return &Finding{
			File: file, Service: svc, Variable: key,
			Severity: "medium", Category: "wildcard_bind",
			Message: fmt.Sprintf("%s binds to all interfaces (%s)", key, val),
			Line: line,
		}
	}
	return nil
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Environment Variable Security Scan\n")
	b.WriteString(strings.Repeat("=", 62) + "\n\n")

	if r.Summary.TotalVars == 0 {
		b.WriteString("  No environment variables found.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "  Files checked:     %d\n", r.Summary.FilesChecked)
	fmt.Fprintf(&b, "  Total variables:   %d\n", r.Summary.TotalVars)
	fmt.Fprintf(&b, "  Findings:          %d\n", r.Summary.TotalFindings)
	if r.Summary.CriticalCount > 0 {
		fmt.Fprintf(&b, "  Critical:          %d\n", r.Summary.CriticalCount)
	}
	if r.Summary.HighCount > 0 {
		fmt.Fprintf(&b, "  High:              %d\n", r.Summary.HighCount)
	}
	if r.Summary.MediumCount > 0 {
		fmt.Fprintf(&b, "  Medium:            %d\n", r.Summary.MediumCount)
	}
	b.WriteString("\n")

	if len(r.Findings) > 0 {
		b.WriteString("Findings\n")
		b.WriteString(strings.Repeat("-", 62) + "\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "  [%s] %s/%s: %s\n",
				strings.ToUpper(f.Severity), f.File, f.Service, f.Message)
		}
		b.WriteString("\n")
	}

	return b.String()
}
