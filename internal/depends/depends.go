package depends

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
	Chain    string `json:"chain,omitempty"`
}

type ServiceResult struct {
	Name       string   `json:"name"`
	File       string   `json:"file"`
	DependsOn  []string `json:"depends_on,omitempty"`
	Findings   []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	WithDependencies int `json:"with_dependencies"`
	WithIssues       int `json:"with_issues"`
	TotalFindings    int `json:"total_findings"`
	CircularDeps     int `json:"circular_deps"`
	LongChains       int `json:"long_chains"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func Analyze(collected *collect.Collected) Report {
	var results []ServiceResult
	var total, withDeps, withIssues, totalFindings, circularCount, longCount int

	for i := range collected.ComposeFiles {
		cf := &collected.ComposeFiles[i]
		graph := buildGraph(*cf)
		for _, svc := range cf.Services {
			total++
			sr := ServiceResult{
				Name: svc.Name,
				File: cf.Path,
			}
			deps := sortedKeys(svc.DependsOn)
			sr.DependsOn = deps
			if len(deps) > 0 {
				withDeps++
			}

			// Check for circular dependencies
			if cycle := detectCycle(svc.Name, graph); cycle != "" {
				sr.Findings = append(sr.Findings, Finding{
					Service:  svc.Name,
					File:     cf.Path,
					Severity: "critical",
					RuleID:   "depends_circular",
					Detail:   fmt.Sprintf("circular dependency detected: %s", cycle),
					Chain:    cycle,
				})
				circularCount++
			}

			// Check chain length
			longest := longestChain(svc.Name, graph, nil)
			if longest > 5 {
				chain := traceChain(svc.Name, graph, nil)
				sr.Findings = append(sr.Findings, Finding{
					Service:  svc.Name,
					File:     cf.Path,
					Severity: "medium",
					RuleID:   "depends_long_chain",
					Detail:   fmt.Sprintf("dependency chain length %d exceeds recommended max of 5", longest),
					Chain:    strings.Join(chain, " -> "),
				})
				longCount++
			}

			// Check for missing healthcheck conditions
			for depName, cond := range svc.DependsOn {
				if cond.Condition == "" || cond.Condition == "service_started" {
					sr.Findings = append(sr.Findings, Finding{
						Service:  svc.Name,
						File:     cf.Path,
						Severity: "medium",
						RuleID:   "depends_no_healthcheck",
						Detail:   fmt.Sprintf("depends on '%s' without service_healthy condition; service may start before dependency is ready", depName),
					})
				}
			}

			// Check for single point of failure (service depended on by 3+ others)
			dependents := countDependents(svc.Name, cf.Services)
			if dependents >= 3 {
				sr.Findings = append(sr.Findings, Finding{
					Service:  svc.Name,
					File:     cf.Path,
					Severity: "low",
					RuleID:   "depends_single_point",
					Detail:   fmt.Sprintf("service is depended on by %d others; single point of failure", dependents),
				})
			}

			if len(sr.Findings) > 0 {
				withIssues++
				totalFindings += len(sr.Findings)
			}
			results = append(results, sr)
		}
		_ = graph
	}

	return Report{
		Services: results,
		Summary: Summary{
			TotalServices:    total,
			WithDependencies: withDeps,
			WithIssues:       withIssues,
			TotalFindings:    totalFindings,
			CircularDeps:     circularCount,
			LongChains:       longCount,
		},
	}
}

func buildGraph(cf compose.File) map[string][]string {
	g := map[string][]string{}
	for _, svc := range cf.Services {
		deps := sortedKeys(svc.DependsOn)
		g[svc.Name] = deps
	}
	return g
}

func detectCycle(start string, graph map[string][]string) string {
	visited := map[string]bool{}
	path := []string{}
	var dfs func(node string) string
	dfs = func(node string) string {
		if visited[node] {
			// Find the cycle start in path
			for i, p := range path {
				if p == node {
					cycle := append(path[i:], node)
					return strings.Join(cycle, " -> ")
				}
			}
			return ""
		}
		visited[node] = true
		path = append(path, node)
		for _, dep := range graph[node] {
			if result := dfs(dep); result != "" {
				return result
			}
		}
		path = path[:len(path)-1]
		visited[node] = false
		return ""
	}
	return dfs(start)
}

func longestChain(node string, graph map[string][]string, visited map[string]bool) int {
	if visited == nil {
		visited = map[string]bool{}
	}
	if visited[node] {
		return 0
	}
	visited[node] = true
	max := 0
	for _, dep := range graph[node] {
		depth := longestChain(dep, graph, visited)
		if depth > max {
			max = depth
		}
	}
	visited[node] = false
	return max + 1
}

func traceChain(node string, graph map[string][]string, visited map[string]bool) []string {
	if visited == nil {
		visited = map[string]bool{}
	}
	if visited[node] {
		return nil
	}
	visited[node] = true
	chain := []string{node}
	bestSub := []string{}
	for _, dep := range graph[node] {
		sub := traceChain(dep, graph, visited)
		if len(sub) > len(bestSub) {
			bestSub = sub
		}
	}
	visited[node] = false
	return append(chain, bestSub...)
}

func countDependents(name string, services []compose.Service) int {
	count := 0
	for _, svc := range services {
		if _, ok := svc.DependsOn[name]; ok {
			count++
		}
	}
	return count
}

func sortedKeys(m map[string]compose.DependsOnCondition) []string {
	if m == nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Service Dependency Chain Analysis\n")
	sb.WriteString(strings.Repeat("=", 62) + "\n\n")
	sb.WriteString(fmt.Sprintf("  Total services:       %d\n", r.Summary.TotalServices))
	sb.WriteString(fmt.Sprintf("  With dependencies:    %d\n", r.Summary.WithDependencies))
	sb.WriteString(fmt.Sprintf("  Services with issues: %d\n", r.Summary.WithIssues))
	sb.WriteString(fmt.Sprintf("  Total findings:       %d\n", r.Summary.TotalFindings))
	sb.WriteString(fmt.Sprintf("  Circular deps:        %d\n", r.Summary.CircularDeps))
	sb.WriteString(fmt.Sprintf("  Long chains (>5):     %d\n\n", r.Summary.LongChains))

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s (%s)\n", sr.Name, sr.File))
		for _, f := range sr.Findings {
			sb.WriteString(fmt.Sprintf("    [%s] %s: %s\n", strings.ToUpper(f.Severity), f.RuleID, f.Detail))
			if f.Chain != "" {
				sb.WriteString(fmt.Sprintf("      chain: %s\n", f.Chain))
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
