package depguard

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
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices     int `json:"total_services"`
	TotalFindings     int `json:"total_findings"`
	NoHealthcheck     int `json:"no_healthcheck"`
	RestartMismatch   int `json:"restart_mismatch"`
	MissingCondition  int `json:"missing_condition"`
	CriticalChain     int `json:"critical_chain"`
	CircularRisk      int `json:"circular_risk"`
	OrphanDependency  int `json:"orphan_dependency"`
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		svcMap := buildServiceMap(cf.Services)
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, svcMap)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func buildServiceMap(services []compose.Service) map[string]compose.Service {
	m := make(map[string]compose.Service, len(services))
	for _, s := range services {
		m[s.Name] = s
	}
	return m
}

func analyzeService(svc compose.Service, file string, svcMap map[string]compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for depName := range svc.DependsOn {
		dep, exists := svcMap[depName]
		if !exists {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "dep_orphan",
				Message: fmt.Sprintf("Service '%s' depends on '%s' which is not defined in the compose file", svc.Name, depName),
			})
			continue
		}

		if dep.Healthcheck == nil {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "dep_no_healthcheck",
				Message: fmt.Sprintf("Service '%s' depends on '%s' which has no healthcheck; service may start before dependency is ready", svc.Name, depName),
			})
		}

		cond := svc.DependsOn[depName]
		if cond.Condition == "" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "dep_missing_condition",
				Message: fmt.Sprintf("Service '%s' depends on '%s' without a start condition; defaults to 'service_started' which does not wait for readiness", svc.Name, depName),
			})
		}

		if isAlwaysRestart(svc.Restart) && isNoRestart(dep.Restart) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "dep_restart_mismatch",
				Message: fmt.Sprintf("Service '%s' restarts always but dependency '%s' has no restart policy; dependency failure leaves dependent in a crash loop", svc.Name, depName),
			})
		}
	}

	chain := depthChain(svc.Name, svcMap, make(map[string]bool))
	if chain > 4 {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "dep_critical_chain",
			Message: fmt.Sprintf("Service '%s' has a dependency chain of depth %d; long chains delay startup and amplify failure propagation", svc.Name, chain),
		})
	}

	if detectCycle(svc.Name, svcMap) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "dep_circular_risk",
			Message: fmt.Sprintf("Service '%s' is part of a circular dependency chain; compose may deadlock on startup", svc.Name),
		})
	}

	return sr
}

func isAlwaysRestart(r string) bool {
	r = strings.ToLower(strings.TrimSpace(r))
	return r == "always" || r == "unless-stopped"
}

func isNoRestart(r string) bool {
	r = strings.ToLower(strings.TrimSpace(r))
	return r == "" || r == "no"
}

func depthChain(name string, svcMap map[string]compose.Service, visited map[string]bool) int {
	if visited[name] {
		return 0
	}
	visited[name] = true
	svc, ok := svcMap[name]
	if !ok {
		return 0
	}
	maxDepth := 0
	for dep := range svc.DependsOn {
		d := depthChain(dep, svcMap, visited)
		if d > maxDepth {
			maxDepth = d
		}
	}
	return maxDepth + 1
}

func detectCycle(start string, svcMap map[string]compose.Service) bool {
	visited := make(map[string]bool)
	stack := make(map[string]bool)
	return hasCycle(start, svcMap, visited, stack)
}

func hasCycle(name string, svcMap map[string]compose.Service, visited, stack map[string]bool) bool {
	visited[name] = true
	stack[name] = true
	svc, ok := svcMap[name]
	if !ok {
		stack[name] = false
		return false
	}
	for dep := range svc.DependsOn {
		if !visited[dep] {
			if hasCycle(dep, svcMap, visited, stack) {
				return true
			}
		} else if stack[dep] {
			return true
		}
	}
	stack[name] = false
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "dep_no_healthcheck":
				s.NoHealthcheck++
			case "dep_restart_mismatch":
				s.RestartMismatch++
			case "dep_missing_condition":
				s.MissingCondition++
			case "dep_critical_chain":
				s.CriticalChain++
			case "dep_circular_risk":
				s.CircularRisk++
			case "dep_orphan":
				s.OrphanDependency++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Dependency Guard Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Missing healthchecks:   %d\n", r.Summary.NoHealthcheck)
	fmt.Fprintf(&b, "  Restart mismatches:     %d\n", r.Summary.RestartMismatch)
	fmt.Fprintf(&b, "  Missing conditions:     %d\n", r.Summary.MissingCondition)
	fmt.Fprintf(&b, "  Critical chains:        %d\n", r.Summary.CriticalChain)
	fmt.Fprintf(&b, "  Circular risks:         %d\n", r.Summary.CircularRisk)
	fmt.Fprintf(&b, "  Orphan dependencies:    %d\n\n", r.Summary.OrphanDependency)
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
