package graphqlaudit

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service string
	Rule    string
	Detail  string
}

type ServiceResult struct {
	Service  string
	Findings []Finding
}

type Summary struct {
	TotalServices    int
	TotalFindings    int
	AffectedServices int
	ByRule           map[string]int
}

type Report struct {
	Results []ServiceResult
	Summary Summary
}

type ruleInfo struct {
	ID string
}

var ruleIntrospection = ruleInfo{ID: "GRAPHQL-001"}
var ruleNoDepthLimit = ruleInfo{ID: "GRAPHQL-002"}
var ruleNoComplexityLimit = ruleInfo{ID: "GRAPHQL-003"}
var ruleDebugMode = ruleInfo{ID: "GRAPHQL-004"}
var ruleNoRateLimit = ruleInfo{ID: "GRAPHQL-005"}
var ruleBatchNoLimit = ruleInfo{ID: "GRAPHQL-006"}

func isGraphQLService(svc compose.Service) bool {
	combined := strings.ToLower(svc.Image + " " + strings.Join(svc.Command, " ") + " " + strings.Join(svc.Entrypoint, " "))
	for _, e := range svc.Environment {
		combined += " " + strings.ToLower(e)
	}
	return strings.Contains(combined, "graphql") || strings.Contains(combined, "apollo") || strings.Contains(combined, "hasura")
}

func envVal(svc compose.Service, keys ...string) (string, bool) {
	for _, e := range svc.Environment {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.ToUpper(strings.TrimSpace(parts[0]))
		for _, key := range keys {
			if k == key {
				return strings.TrimSpace(parts[1]), true
			}
		}
	}
	return "", false
}

func envExists(svc compose.Service, keys ...string) bool {
	_, found := envVal(svc, keys...)
	return found
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name}

	if !isGraphQLService(svc) {
		return sr
	}

	if v, ok := envVal(svc, "GRAPHQL_INTROSPECTION", "ENABLE_INTROSPECTION", "INTROSPECTION"); ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" || low == "yes" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleIntrospection.ID,
				Detail:  fmt.Sprintf("introspection explicitly enabled (%s)", v),
			})
		}
	}

	if !envExists(svc, "GRAPHQL_DEPTH_LIMIT", "MAX_QUERY_DEPTH", "QUERY_DEPTH_LIMIT") {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleNoDepthLimit.ID,
			Detail:  "no query depth limit environment variable found",
		})
	}

	if !envExists(svc, "GRAPHQL_COMPLEXITY_LIMIT", "MAX_QUERY_COMPLEXITY", "QUERY_COMPLEXITY_LIMIT") {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleNoComplexityLimit.ID,
			Detail:  "no query complexity limit environment variable found",
		})
	}

	if v, ok := envVal(svc, "GRAPHQL_DEBUG", "DEBUG"); ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleDebugMode.ID,
				Detail:  "GraphQL debug mode enabled",
			})
		}
	}
	if v, ok := envVal(svc, "GRAPHQL_PLAYGROUND", "ENABLE_PLAYGROUND"); ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleDebugMode.ID,
				Detail:  "GraphQL playground enabled",
			})
		}
	}

	if !envExists(svc, "GRAPHQL_RATE_LIMIT", "RATE_LIMIT", "QUERY_RATE_LIMIT") {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleNoRateLimit.ID,
			Detail:  "no rate limiting configured for GraphQL endpoint",
		})
	}

	if v, ok := envVal(svc, "GRAPHQL_BATCH", "ENABLE_BATCH", "BATCH_QUERIES"); ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" {
			if !envExists(svc, "GRAPHQL_BATCH_LIMIT", "BATCH_LIMIT", "MAX_BATCH_SIZE") {
				sr.Findings = append(sr.Findings, Finding{
					Service: svc.Name,
					Rule:    ruleBatchNoLimit.ID,
					Detail:  "batch queries enabled without size limit",
				})
			}
		}
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	var results []ServiceResult
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			results = append(results, sr)
		}
	}
	return Report{Results: results, Summary: summarize(results)}
}

func summarize(results []ServiceResult) Summary {
	s := Summary{ByRule: map[string]int{}}
	s.TotalServices = len(results)
	for _, r := range results {
		if len(r.Findings) > 0 {
			s.AffectedServices++
		}
		for _, f := range r.Findings {
			s.TotalFindings++
			s.ByRule[f.Rule]++
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("GraphQL Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Services scanned:   %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Services affected:  %d\n", r.Summary.AffectedServices)
	fmt.Fprintf(&b, "  Total findings:     %d\n\n", r.Summary.TotalFindings)

	for _, sr := range r.Results {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s\n", sr.Service)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Rule, f.Detail)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
