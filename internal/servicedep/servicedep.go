package servicedep

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type ServiceNode struct {
	Name       string   `json:"name"`
	DependsOn  []string `json:"depends_on"`
	Dependents []string `json:"dependents"`
	Depth      int      `json:"depth"`
}

type DepFinding struct {
	Service  string `json:"service"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type Summary struct {
	TotalServices    int    `json:"total_services"`
	TotalDependencies int   `json:"total_dependencies"`
	MaxDepth         int    `json:"max_depth"`
	CircularDeps     int    `json:"circular_deps"`
	Findings         int    `json:"findings"`
	HighSev          int    `json:"high_severity"`
	MediumSev        int    `json:"medium_severity"`
	LowSev           int    `json:"low_severity"`
	Score            int    `json:"score"`
	Grade            string `json:"grade"`
}

type Report struct {
	Nodes    []ServiceNode `json:"nodes"`
	Findings []DepFinding  `json:"findings"`
	Summary  Summary       `json:"summary"`
}

func Analyze(collected *collect.Collected) Report {
	adj := map[string][]string{}
	allServices := map[string]bool{}

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			allServices[svc.Name] = true
			for dep := range svc.DependsOn {
				adj[svc.Name] = append(adj[svc.Name], dep)
			}
		}
	}

	reverse := map[string][]string{}
	totalDeps := 0
	for svc, deps := range adj {
		totalDeps += len(deps)
		for _, dep := range deps {
			reverse[dep] = append(reverse[dep], svc)
		}
	}

	depths := computeDepths(allServices, adj)
	cycles := detectCycles(allServices, adj)

	var findings []DepFinding

	for _, cycle := range cycles {
		findings = append(findings, DepFinding{
			Service:  cycle[0],
			Category: "circular",
			Severity: "high",
			Message:  fmt.Sprintf("Circular dependency: %s", strings.Join(cycle, " -> ")),
		})
	}

	maxDepth := 0
	for _, d := range depths {
		if d > maxDepth {
			maxDepth = d
		}
	}

	for svc, d := range depths {
		if d > 5 {
			findings = append(findings, DepFinding{
				Service:  svc,
				Category: "long-chain",
				Severity: "medium",
				Message:  fmt.Sprintf("Dependency chain depth %d exceeds threshold of 5", d),
			})
		}
	}

	for svc := range allServices {
		dependents := reverse[svc]
		if len(dependents) > 5 {
			findings = append(findings, DepFinding{
				Service:  svc,
				Category: "critical-node",
				Severity: "medium",
				Message:  fmt.Sprintf("Critical node: %d services depend on %s", len(dependents), svc),
			})
		}
		fanOut := len(adj[svc])
		if fanOut > 5 {
			findings = append(findings, DepFinding{
				Service:  svc,
				Category: "fan-out",
				Severity: "low",
				Message:  fmt.Sprintf("Service %s depends on %d other services", svc, fanOut),
			})
		}
	}

	for svc := range allServices {
		if len(adj[svc]) == 0 && len(reverse[svc]) == 0 && len(allServices) > 1 {
			findings = append(findings, DepFinding{
				Service:  svc,
				Category: "orphan",
				Severity: "low",
				Message:  "Service has no dependencies and no dependents (orphan)",
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		si, sj := sevOrd(findings[i].Severity), sevOrd(findings[j].Severity)
		if si != sj {
			return si < sj
		}
		return findings[i].Service < findings[j].Service
	})

	high, med, low := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case "high":
			high++
		case "medium":
			med++
		case "low":
			low++
		}
	}

	score := 100 - high*15 - med*5 - low*2
	if score < 0 {
		score = 0
	}

	var nodes []ServiceNode
	for svc := range allServices {
		nodes = append(nodes, ServiceNode{
			Name:       svc,
			DependsOn:  adj[svc],
			Dependents: reverse[svc],
			Depth:      depths[svc],
		})
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Name < nodes[j].Name
	})

	return Report{
		Nodes:    nodes,
		Findings: findings,
		Summary: Summary{
			TotalServices:    len(allServices),
			TotalDependencies: totalDeps,
			MaxDepth:         maxDepth,
			CircularDeps:     len(cycles),
			Findings:         len(findings),
			HighSev:          high,
			MediumSev:        med,
			LowSev:           low,
			Score:            score,
			Grade:            scoreGrade(score),
		},
	}
}

func computeDepths(services map[string]bool, adj map[string][]string) map[string]int {
	depths := map[string]int{}
	for svc := range services {
		depths[svc] = 0
	}
	maxIter := len(services)
	for iter := 0; iter < maxIter; iter++ {
		changed := false
		for svc, deps := range adj {
			for _, dep := range deps {
				if depths[dep]+1 > depths[svc] {
					depths[svc] = depths[dep] + 1
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	return depths
}

func detectCycles(services map[string]bool, adj map[string][]string) [][]string {
	var cycles [][]string
	visited := map[string]bool{}
	path := map[string]bool{}
	var stack []string

	var dfs func(node string)
	dfs = func(node string) {
		if path[node] {
			var cycle []string
			for i := len(stack) - 1; i >= 0; i-- {
				cycle = append([]string{stack[i]}, cycle...)
				if stack[i] == node {
					break
				}
			}
			cycle = append(cycle, node)
			cycles = append(cycles, cycle)
			return
		}
		if visited[node] {
			return
		}
		visited[node] = true
		path[node] = true
		stack = append(stack, node)
		for _, dep := range adj[node] {
			dfs(dep)
		}
		stack = stack[:len(stack)-1]
		path[node] = false
	}

	sorted := make([]string, 0, len(services))
	for s := range services {
		sorted = append(sorted, s)
	}
	sort.Strings(sorted)
	for _, s := range sorted {
		dfs(s)
	}
	return cycles
}

func sevOrd(s string) int {
	switch s {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}

func scoreGrade(score int) string {
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
	var sb strings.Builder
	sb.WriteString("Service Dependency Analysis\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&sb, "  Services:       %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&sb, "  Dependencies:   %d\n", r.Summary.TotalDependencies)
	fmt.Fprintf(&sb, "  Max depth:      %d\n", r.Summary.MaxDepth)
	fmt.Fprintf(&sb, "  Circular deps:  %d\n", r.Summary.CircularDeps)
	fmt.Fprintf(&sb, "  Findings:       %d\n", r.Summary.Findings)
	fmt.Fprintf(&sb, "  High:           %d\n", r.Summary.HighSev)
	fmt.Fprintf(&sb, "  Medium:         %d\n", r.Summary.MediumSev)
	fmt.Fprintf(&sb, "  Low:            %d\n", r.Summary.LowSev)
	fmt.Fprintf(&sb, "  Score:          %d/100 (%s)\n\n", r.Summary.Score, r.Summary.Grade)

	if len(r.Nodes) > 0 {
		sb.WriteString("Dependency Graph:\n")
		for _, n := range r.Nodes {
			deps := "none"
			if len(n.DependsOn) > 0 {
				deps = strings.Join(n.DependsOn, ", ")
			}
			fmt.Fprintf(&sb, "  %s (depth %d) -> %s\n", n.Name, n.Depth, deps)
		}
		sb.WriteString("\n")
	}

	if len(r.Findings) > 0 {
		sb.WriteString("Findings:\n")
		for i, f := range r.Findings {
			fmt.Fprintf(&sb, "  %d. [%s] %s: %s (%s)\n",
				i+1, strings.ToUpper(f.Severity), f.Service, f.Message, f.Category)
		}
	}

	return sb.String()
}
