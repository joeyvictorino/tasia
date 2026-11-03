package depchain

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
	Service    string              `json:"service"`
	File       string              `json:"file"`
	DependsOn  []string            `json:"depends_on"`
	Conditions map[string]string   `json:"conditions"`
	Findings   []Finding           `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	NoDeps           int `json:"no_deps"`
	WeakConditions   int `json:"weak_conditions"`
	MissingHealthDep int `json:"missing_health_dep"`
	CircularRisk     int `json:"circular_risk"`
	TotalFindings    int `json:"total_findings"`
}

var securityCriticalImages = []string{
	"envoy", "nginx", "traefik", "haproxy", "caddy",
	"vault", "keycloak", "authelia", "oauth2-proxy",
	"postgres", "mysql", "redis", "mongodb", "milvus",
	"chromadb", "weaviate", "qdrant", "pinecone",
}

func isSecurityCritical(image string) bool {
	lower := strings.ToLower(image)
	for _, s := range securityCriticalImages {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		svcMap := make(map[string]compose.Service)
		for _, svc := range cf.Services {
			svcMap[svc.Name] = svc
		}
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path, svcMap)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string, svcMap map[string]compose.Service) ServiceResult {
	sr := ServiceResult{
		Service:    svc.Name,
		File:       file,
		Conditions: make(map[string]string),
	}

	if len(svc.DependsOn) == 0 {
		if isAgentLike(svc) && hasSecurityDep(svcMap) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "dep_chain_missing",
				Message: fmt.Sprintf("Agent service '%s' has no depends_on; may start before security-critical services are ready", svc.Name),
			})
		}
		return sr
	}

	for dep, cond := range svc.DependsOn {
		sr.DependsOn = append(sr.DependsOn, dep)
		sr.Conditions[dep] = cond.Condition

		if cond.Condition == "" || cond.Condition == "service_started" {
			depSvc, exists := svcMap[dep]
			if exists && isSecurityCritical(depSvc.Image) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "dep_chain_weak_condition",
					Message: fmt.Sprintf("Service '%s' depends on security-critical '%s' with weak condition '%s'; use service_healthy", svc.Name, dep, conditionLabel(cond.Condition)),
				})
			}
		}

		depSvc, exists := svcMap[dep]
		if exists && cond.Condition == "service_healthy" && depSvc.Healthcheck == nil {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "dep_chain_no_healthcheck",
				Message: fmt.Sprintf("Service '%s' depends on '%s' with service_healthy but '%s' has no healthcheck defined", svc.Name, dep, dep),
			})
		}
	}

	return sr
}

func conditionLabel(c string) string {
	if c == "" {
		return "service_started"
	}
	return c
}

func isAgentLike(svc compose.Service) bool {
	lower := strings.ToLower(svc.Image + " " + svc.Name)
	agentIndicators := []string{"agent", "llm", "openai", "anthropic", "langchain", "autogpt", "crewai"}
	for _, ind := range agentIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func hasSecurityDep(svcMap map[string]compose.Service) bool {
	for _, svc := range svcMap {
		if isSecurityCritical(svc.Image) {
			return true
		}
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		if len(sr.DependsOn) == 0 {
			s.NoDeps++
		}
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "dep_chain_weak_condition":
				s.WeakConditions++
			case "dep_chain_no_healthcheck":
				s.MissingHealthDep++
			case "dep_chain_missing":
				s.NoDeps++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Dependency Chain Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No dependencies:      %d\n", r.Summary.NoDeps)
	fmt.Fprintf(&b, "  Weak conditions:      %d\n", r.Summary.WeakConditions)
	fmt.Fprintf(&b, "  Missing healthchecks: %d\n\n", r.Summary.MissingHealthDep)
	for _, sr := range r.Services {
		deps := "none"
		if len(sr.DependsOn) > 0 {
			deps = strings.Join(sr.DependsOn, ", ")
		}
		fmt.Fprintf(&b, "  %-30s depends_on: %s\n", sr.Service, deps)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
