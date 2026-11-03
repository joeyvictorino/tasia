package deporder

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type FileResult struct {
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path    string       `json:"path"`
	Files   []FileResult `json:"files"`
	Summary Summary      `json:"summary"`
}

type Summary struct {
	TotalFiles    int `json:"total_files"`
	TotalFindings int `json:"total_findings"`
	Cycles        int `json:"cycles"`
	MissingDeps   int `json:"missing_deps"`
	NoDependsOn   int `json:"no_depends_on"`
}

func analyzeFile(cf compose.File) FileResult {
	fr := FileResult{File: cf.Path}

	names := map[string]bool{}
	for _, svc := range cf.Services {
		names[svc.Name] = true
	}

	hasDeps := false
	for _, svc := range cf.Services {
		if len(svc.DependsOn) > 0 {
			hasDeps = true
			for dep := range svc.DependsOn {
				if !names[dep] {
					fr.Findings = append(fr.Findings, Finding{
						Level:   "warning",
						Rule:    "missing_dependency",
						Message: fmt.Sprintf("service %q depends on %q which is not defined in %s", svc.Name, dep, cf.Path),
					})
				}
			}
		}
	}

	cycles := detectCycles(cf.Services)
	for _, cycle := range cycles {
		fr.Findings = append(fr.Findings, Finding{
			Level:   "warning",
			Rule:    "dependency_cycle",
			Message: fmt.Sprintf("dependency cycle detected in %s: %s", cf.Path, strings.Join(cycle, " -> ")),
		})
	}

	if !hasDeps && len(cf.Services) > 1 {
		fr.Findings = append(fr.Findings, Finding{
			Level:   "info",
			Rule:    "no_depends_on",
			Message: fmt.Sprintf("%s has %d services with no depends_on declarations — startup order is undefined", cf.Path, len(cf.Services)),
		})
	}

	return fr
}

func detectCycles(services []compose.Service) [][]string {
	graph := map[string][]string{}
	for _, svc := range services {
		deps := make([]string, 0, len(svc.DependsOn))
		for d := range svc.DependsOn {
			deps = append(deps, d)
		}
		sort.Strings(deps)
		graph[svc.Name] = deps
	}

	var cycles [][]string
	visited := map[string]int{} // 0=unvisited, 1=in-stack, 2=done

	var dfs func(node string, path []string) bool
	dfs = func(node string, path []string) bool {
		visited[node] = 1
		path = append(path, node)
		for _, dep := range graph[node] {
			if visited[dep] == 1 {
				start := 0
				for i, p := range path {
					if p == dep {
						start = i
						break
					}
				}
				cycle := append(path[start:], dep)
				cycles = append(cycles, cycle)
				return true
			}
			if visited[dep] == 0 {
				if dfs(dep, path) {
					return true
				}
			}
		}
		visited[node] = 2
		return false
	}

	names := make([]string, 0, len(graph))
	for n := range graph {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		if visited[n] == 0 {
			dfs(n, nil)
		}
	}
	return cycles
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		fr := analyzeFile(cf)
		r.Files = append(r.Files, fr)
	}
	r.Summary = summarize(r.Files)
	return r
}

func summarize(files []FileResult) Summary {
	s := Summary{TotalFiles: len(files)}
	for _, fr := range files {
		for _, f := range fr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "dependency_cycle":
				s.Cycles++
			case "missing_dependency":
				s.MissingDeps++
			case "no_depends_on":
				s.NoDependsOn++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Dependency Order Analysis\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	b.WriteString(fmt.Sprintf("Root: %s\n", r.Path))
	b.WriteString(fmt.Sprintf("Compose files: %d  Findings: %d\n\n",
		r.Summary.TotalFiles, r.Summary.TotalFindings))

	for _, fr := range r.Files {
		if len(fr.Findings) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("File: %s\n", fr.File))
		for _, f := range fr.Findings {
			b.WriteString(fmt.Sprintf("  [%s] %s: %s\n", f.Level, f.Rule, f.Message))
		}
		b.WriteString("\n")
	}

	return b.String()
}
