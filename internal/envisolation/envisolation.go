package envisolation

import (
	"fmt"
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
	Name           string    `json:"name"`
	File           string    `json:"file"`
	EnvCount       int       `json:"env_count"`
	SharedCount    int       `json:"shared_count"`
	IsolationScore int       `json:"isolation_score"`
	Findings       []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices  int `json:"total_services"`
	WithEnvVars    int `json:"with_env_vars"`
	WithIssues     int `json:"with_issues"`
	TotalFindings  int `json:"total_findings"`
	AvgIsolation   int `json:"avg_isolation_score"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func Analyze(collected *collect.Collected) Report {
	var results []ServiceResult
	var totalSvcs, withEnv, withIssues, totalFindings, scoreSum int

	for i := range collected.ComposeFiles {
		cf := &collected.ComposeFiles[i]
		envIndex := buildEnvIndex(cf.Services)

		for _, svc := range cf.Services {
			totalSvcs++
			sr := ServiceResult{
				Name:     svc.Name,
				File:     cf.Path,
				EnvCount: len(svc.Environment),
			}
			if len(svc.Environment) > 0 {
				withEnv++
			}

			shared := findSharedVars(svc.Name, svc.Environment, envIndex)
			sr.SharedCount = len(shared)

			for _, sv := range shared {
				sr.Findings = append(sr.Findings, Finding{
					Service:  svc.Name,
					File:     cf.Path,
					Severity: classifySharedSeverity(sv.key),
					RuleID:   "env_shared_var",
					Detail:   fmt.Sprintf("env var '%s' shared with %s", sv.key, strings.Join(sv.others, ", ")),
				})
			}

			sensitiveLeak := findSensitiveLeaks(svc.Environment)
			for _, key := range sensitiveLeak {
				sr.Findings = append(sr.Findings, Finding{
					Service:  svc.Name,
					File:     cf.Path,
					Severity: "high",
					RuleID:   "env_sensitive_exposed",
					Detail:   fmt.Sprintf("sensitive env var '%s' set directly instead of via secrets", key),
				})
			}

			score := calcIsolationScore(len(svc.Environment), sr.SharedCount, len(sensitiveLeak))
			sr.IsolationScore = score
			scoreSum += score

			if len(sr.Findings) > 0 {
				withIssues++
				totalFindings += len(sr.Findings)
			}
			results = append(results, sr)
		}
	}

	avg := 0
	if totalSvcs > 0 {
		avg = scoreSum / totalSvcs
	}

	return Report{
		Services: results,
		Summary: Summary{
			TotalServices: totalSvcs,
			WithEnvVars:   withEnv,
			WithIssues:    withIssues,
			TotalFindings: totalFindings,
			AvgIsolation:  avg,
		},
	}
}

type sharedVar struct {
	key    string
	others []string
}

func buildEnvIndex(services []compose.Service) map[string][]string {
	idx := map[string][]string{}
	for _, svc := range services {
		for _, entry := range svc.Environment {
			key := envKey(entry)
			idx[key] = append(idx[key], svc.Name)
		}
	}
	return idx
}

func findSharedVars(name string, env []string, idx map[string][]string) []sharedVar {
	var result []sharedVar
	seen := map[string]bool{}
	for _, entry := range env {
		key := envKey(entry)
		if seen[key] {
			continue
		}
		seen[key] = true
		users := idx[key]
		if len(users) <= 1 {
			continue
		}
		var others []string
		for _, u := range users {
			if u != name {
				others = append(others, u)
			}
		}
		if len(others) > 0 {
			sort.Strings(others)
			result = append(result, sharedVar{key: key, others: others})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].key < result[j].key })
	return result
}

var sensitivePatterns = []string{
	"PASSWORD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
	"PRIVATE_KEY", "AUTH", "CREDENTIAL", "ACCESS_KEY",
}

func findSensitiveLeaks(env []string) []string {
	var result []string
	for _, entry := range env {
		key := envKey(entry)
		upper := strings.ToUpper(key)
		for _, pat := range sensitivePatterns {
			if strings.Contains(upper, pat) {
				result = append(result, key)
				break
			}
		}
	}
	sort.Strings(result)
	return result
}

func classifySharedSeverity(key string) string {
	upper := strings.ToUpper(key)
	for _, pat := range sensitivePatterns {
		if strings.Contains(upper, pat) {
			return "high"
		}
	}
	return "low"
}

func calcIsolationScore(total, shared, sensitive int) int {
	if total == 0 {
		return 100
	}
	penalty := (shared * 15) + (sensitive * 25)
	score := 100 - penalty
	if score < 0 {
		return 0
	}
	return score
}

func envKey(entry string) string {
	if idx := strings.IndexByte(entry, '='); idx >= 0 {
		return entry[:idx]
	}
	return entry
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Environment Variable Isolation Analysis\n")
	sb.WriteString(strings.Repeat("=", 62) + "\n\n")
	sb.WriteString(fmt.Sprintf("  Total services:       %d\n", r.Summary.TotalServices))
	sb.WriteString(fmt.Sprintf("  With env vars:        %d\n", r.Summary.WithEnvVars))
	sb.WriteString(fmt.Sprintf("  Services with issues: %d\n", r.Summary.WithIssues))
	sb.WriteString(fmt.Sprintf("  Total findings:       %d\n", r.Summary.TotalFindings))
	sb.WriteString(fmt.Sprintf("  Avg isolation score:  %d/100\n\n", r.Summary.AvgIsolation))

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s (%s) — score: %d/100\n", sr.Name, sr.File, sr.IsolationScore))
		for _, f := range sr.Findings {
			sb.WriteString(fmt.Sprintf("    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Detail))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
