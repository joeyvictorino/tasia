package buildargs

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service  string `json:"service"`
	File     string `json:"file"`
	Severity string `json:"severity"`
	RuleID   string `json:"rule_id"`
	Detail   string `json:"detail"`
}

type ServiceResult struct {
	Name     string    `json:"name"`
	File     string    `json:"file"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices   int `json:"total_services"`
	WithEnvVars     int `json:"with_env_vars"`
	WithIssues      int `json:"with_issues"`
	TotalFindings   int `json:"total_findings"`
	HardcodedCreds  int `json:"hardcoded_creds"`
	WeakDefaults    int `json:"weak_defaults"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var secretPatterns = []string{
	"PASSWORD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
	"PRIVATE_KEY", "CREDENTIAL", "ACCESS_KEY", "AUTH_TOKEN",
}

var weakDefaultRe = regexp.MustCompile(`(?i)^(password|secret|admin|root|test|changeme|default|123456|qwerty)$`)

var inlineSecretRe = regexp.MustCompile(`(?i)(password|secret|token|key|credential)=.+`)

func Analyze(collected *collect.Collected) Report {
	var results []ServiceResult
	var totalSvcs, withEnv, withIssues, totalFindings, hardcoded, weakDefaults int

	for i := range collected.ComposeFiles {
		cf := &collected.ComposeFiles[i]
		for _, svc := range cf.Services {
			totalSvcs++
			sr := ServiceResult{
				Name: svc.Name,
				File: cf.Path,
			}

			if len(svc.Environment) > 0 {
				withEnv++
			}

			for _, entry := range svc.Environment {
				key, val := splitEnv(entry)

				if isSecretKey(key) && val != "" && !isVariableRef(val) {
					sr.Findings = append(sr.Findings, Finding{
						Service:  svc.Name,
						File:     cf.Path,
						Severity: "critical",
						RuleID:   "buildargs_hardcoded_secret",
						Detail:   fmt.Sprintf("hardcoded secret in '%s'; use docker secrets or env_file", key),
					})
					hardcoded++
				}

				if isSecretKey(key) && val != "" && weakDefaultRe.MatchString(val) {
					sr.Findings = append(sr.Findings, Finding{
						Service:  svc.Name,
						File:     cf.Path,
						Severity: "high",
						RuleID:   "buildargs_weak_default",
						Detail:   fmt.Sprintf("weak default value for '%s'; easily guessable", key),
					})
					weakDefaults++
				}

				if val != "" && looksLikeBase64Key(val) {
					sr.Findings = append(sr.Findings, Finding{
						Service:  svc.Name,
						File:     cf.Path,
						Severity: "high",
						RuleID:   "buildargs_embedded_key",
						Detail:   fmt.Sprintf("env var '%s' appears to contain an embedded key or token", key),
					})
				}
			}

			checkEntrypointSecrets(svc, cf.Path, &sr)

			if len(sr.Findings) > 0 {
				withIssues++
				totalFindings += len(sr.Findings)
			}
			results = append(results, sr)
		}
	}

	return Report{
		Services: results,
		Summary: Summary{
			TotalServices:  totalSvcs,
			WithEnvVars:    withEnv,
			WithIssues:     withIssues,
			TotalFindings:  totalFindings,
			HardcodedCreds: hardcoded,
			WeakDefaults:   weakDefaults,
		},
	}
}

func checkEntrypointSecrets(svc compose.Service, path string, sr *ServiceResult) {
	combined := strings.Join(svc.Entrypoint, " ") + " " + strings.Join(svc.Command, " ")
	if inlineSecretRe.MatchString(combined) {
		sr.Findings = append(sr.Findings, Finding{
			Service:  svc.Name,
			File:     path,
			Severity: "high",
			RuleID:   "buildargs_runtime_leak",
			Detail:   "secret appears to be passed inline via entrypoint/command arguments",
		})
	}
}

func splitEnv(entry string) (string, string) {
	if idx := strings.IndexByte(entry, '='); idx >= 0 {
		return entry[:idx], entry[idx+1:]
	}
	return entry, ""
}

func isSecretKey(key string) bool {
	upper := strings.ToUpper(key)
	for _, pat := range secretPatterns {
		if strings.Contains(upper, pat) {
			return true
		}
	}
	return false
}

func isVariableRef(val string) bool {
	return strings.HasPrefix(val, "${") || strings.HasPrefix(val, "$")
}

var base64KeyRe = regexp.MustCompile(`^[A-Za-z0-9+/]{32,}={0,2}$`)

func looksLikeBase64Key(val string) bool {
	if len(val) < 32 {
		return false
	}
	return base64KeyRe.MatchString(val)
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Build Arguments & Environment Secret Analysis\n")
	sb.WriteString(strings.Repeat("=", 62) + "\n\n")
	sb.WriteString(fmt.Sprintf("  Total services:       %d\n", r.Summary.TotalServices))
	sb.WriteString(fmt.Sprintf("  With env vars:        %d\n", r.Summary.WithEnvVars))
	sb.WriteString(fmt.Sprintf("  Services with issues: %d\n", r.Summary.WithIssues))
	sb.WriteString(fmt.Sprintf("  Total findings:       %d\n", r.Summary.TotalFindings))
	sb.WriteString(fmt.Sprintf("  Hardcoded creds:      %d\n", r.Summary.HardcodedCreds))
	sb.WriteString(fmt.Sprintf("  Weak defaults:        %d\n\n", r.Summary.WeakDefaults))

	svcs := make([]ServiceResult, len(r.Services))
	copy(svcs, r.Services)
	sort.Slice(svcs, func(i, j int) bool {
		return len(svcs[j].Findings) < len(svcs[i].Findings)
	})

	for _, sr := range svcs {
		if len(sr.Findings) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s (%s)\n", sr.Name, sr.File))
		for _, f := range sr.Findings {
			sb.WriteString(fmt.Sprintf("    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Detail))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
