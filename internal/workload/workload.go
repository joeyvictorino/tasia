package workload

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type WorkloadClass string

const (
	ClassDatabase    WorkloadClass = "database"
	ClassCache       WorkloadClass = "cache"
	ClassWebServer   WorkloadClass = "web-server"
	ClassReverseProxy WorkloadClass = "reverse-proxy"
	ClassMessageQueue WorkloadClass = "message-queue"
	ClassAIModel     WorkloadClass = "ai-model"
	ClassAgentRuntime WorkloadClass = "agent-runtime"
	ClassVectorDB    WorkloadClass = "vector-db"
	ClassMonitoring  WorkloadClass = "monitoring"
	ClassStorage     WorkloadClass = "storage"
	ClassUnknown     WorkloadClass = "unknown"
)

type Finding struct {
	Service     string `json:"service"`
	Source      string `json:"source"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Line        int    `json:"line,omitempty"`
	Remediation string `json:"remediation"`
}

type ServiceProfile struct {
	Service   string        `json:"service"`
	Source    string        `json:"source"`
	Image     string        `json:"image,omitempty"`
	Class     WorkloadClass `json:"class"`
	Findings  []Finding     `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices int            `json:"total_services"`
	ByClass       map[string]int `json:"by_class"`
	Unclassified  int            `json:"unclassified"`
	TotalFindings int            `json:"total_findings"`
}

type Report struct {
	Services []ServiceProfile `json:"services"`
	Summary  Summary          `json:"summary"`
}

var imageClassifiers = []struct {
	pattern string
	class   WorkloadClass
}{
	{"postgres", ClassDatabase},
	{"mysql", ClassDatabase},
	{"mariadb", ClassDatabase},
	{"mongo", ClassDatabase},
	{"cockroach", ClassDatabase},
	{"cassandra", ClassDatabase},
	{"neo4j", ClassDatabase},
	{"influxdb", ClassDatabase},
	{"timescaledb", ClassDatabase},
	{"redis", ClassCache},
	{"memcached", ClassCache},
	{"valkey", ClassCache},
	{"dragonfly", ClassCache},
	{"nginx", ClassReverseProxy},
	{"caddy", ClassReverseProxy},
	{"traefik", ClassReverseProxy},
	{"haproxy", ClassReverseProxy},
	{"envoy", ClassReverseProxy},
	{"httpd", ClassWebServer},
	{"apache", ClassWebServer},
	{"tomcat", ClassWebServer},
	{"rabbitmq", ClassMessageQueue},
	{"kafka", ClassMessageQueue},
	{"nats", ClassMessageQueue},
	{"activemq", ClassMessageQueue},
	{"pulsar", ClassMessageQueue},
	{"mosquitto", ClassMessageQueue},
	{"ollama", ClassAIModel},
	{"vllm", ClassAIModel},
	{"llama", ClassAIModel},
	{"text-generation-inference", ClassAIModel},
	{"tritonserver", ClassAIModel},
	{"localai", ClassAIModel},
	{"n8n", ClassAgentRuntime},
	{"flowise", ClassAgentRuntime},
	{"langflow", ClassAgentRuntime},
	{"dify", ClassAgentRuntime},
	{"openhands", ClassAgentRuntime},
	{"autogpt", ClassAgentRuntime},
	{"chroma", ClassVectorDB},
	{"weaviate", ClassVectorDB},
	{"qdrant", ClassVectorDB},
	{"milvus", ClassVectorDB},
	{"pinecone", ClassVectorDB},
	{"prometheus", ClassMonitoring},
	{"grafana", ClassMonitoring},
	{"alertmanager", ClassMonitoring},
	{"jaeger", ClassMonitoring},
	{"elasticsearch", ClassMonitoring},
	{"kibana", ClassMonitoring},
	{"minio", ClassStorage},
	{"seaweedfs", ClassStorage},
	{"registry", ClassStorage},
}

func classifyImage(image string) WorkloadClass {
	lower := strings.ToLower(image)
	for _, c := range imageClassifiers {
		if strings.Contains(lower, c.pattern) {
			return c.class
		}
	}
	return ClassUnknown
}

func Analyze(collected *collect.Collected) Report {
	var services []ServiceProfile
	s := Summary{ByClass: map[string]int{}}

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			sp := analyzeService(cf.Path, svc)
			s.TotalServices++
			s.ByClass[string(sp.Class)]++
			if sp.Class == ClassUnknown {
				s.Unclassified++
			}
			s.TotalFindings += len(sp.Findings)
			services = append(services, sp)
		}
	}

	return Report{Services: services, Summary: s}
}

func analyzeService(path string, svc compose.Service) ServiceProfile {
	class := classifyImage(svc.Image)
	sp := ServiceProfile{
		Service: svc.Name,
		Source:  path,
		Image:   svc.Image,
		Class:   class,
	}

	switch class {
	case ClassDatabase:
		if svc.Privileged {
			sp.Findings = append(sp.Findings, Finding{
				Service:     svc.Name,
				Source:      path,
				RuleID:      "db_privileged",
				Severity:    "critical",
				Detail:      "database service runs in privileged mode; unnecessary escalation risk",
				Line:        svc.PrivLine,
				Remediation: "Remove privileged: true from database services",
			})
		}
		if !svc.ReadOnly {
			sp.Findings = append(sp.Findings, Finding{
				Service:     svc.Name,
				Source:      path,
				RuleID:      "db_writable_rootfs",
				Severity:    "low",
				Detail:      "database has writable root filesystem; use read_only with volume mounts",
				Line:        svc.ReadOnlyLine,
				Remediation: "Set read_only: true and mount data directory as a named volume",
			})
		}

	case ClassAIModel, ClassAgentRuntime:
		if svc.Privileged {
			sp.Findings = append(sp.Findings, Finding{
				Service:     svc.Name,
				Source:      path,
				RuleID:      "ai_privileged",
				Severity:    "critical",
				Detail:      fmt.Sprintf("%s service runs privileged; AI workloads should be sandboxed", class),
				Line:        svc.PrivLine,
				Remediation: "Remove privileged: true; use --gpus flag for GPU access instead of full privilege",
			})
		}
		if svc.NetworkMode == "host" {
			sp.Findings = append(sp.Findings, Finding{
				Service:     svc.Name,
				Source:      path,
				RuleID:      "ai_host_network",
				Severity:    "high",
				Detail:      fmt.Sprintf("%s service uses host networking; exposes all host interfaces", class),
				Line:        svc.NetworkModeLine,
				Remediation: "Use bridge networking with explicit port mapping",
			})
		}

	case ClassVectorDB:
		if svc.Privileged {
			sp.Findings = append(sp.Findings, Finding{
				Service:     svc.Name,
				Source:      path,
				RuleID:      "vectordb_privileged",
				Severity:    "critical",
				Detail:      "vector database runs privileged; stores embeddings and should be isolated",
				Line:        svc.PrivLine,
				Remediation: "Remove privileged: true from vector database services",
			})
		}

	case ClassReverseProxy:
		if svc.Privileged {
			sp.Findings = append(sp.Findings, Finding{
				Service:     svc.Name,
				Source:      path,
				RuleID:      "proxy_privileged",
				Severity:    "high",
				Detail:      "reverse proxy runs privileged; edge services are high-value targets",
				Line:        svc.PrivLine,
				Remediation: "Remove privileged: true; bind ports via port mapping instead",
			})
		}
	}

	return sp
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Container Workload Classification\n")
	b.WriteString(strings.Repeat("=", 62) + "\n\n")

	fmt.Fprintf(&b, "  Services analyzed:  %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Unclassified:       %d\n", r.Summary.Unclassified)
	fmt.Fprintf(&b, "  Total findings:     %d\n\n", r.Summary.TotalFindings)

	if len(r.Summary.ByClass) > 0 {
		b.WriteString("  Workload Distribution:\n")
		b.WriteString("  " + strings.Repeat("-", 40) + "\n")
		for class, count := range r.Summary.ByClass {
			fmt.Fprintf(&b, "    %-20s %d\n", class, count)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "  %-20s %-25s %-15s\n", "Service", "Image", "Class")
	b.WriteString("  " + strings.Repeat("-", 60) + "\n")
	for _, sp := range r.Services {
		img := sp.Image
		if len(img) > 25 {
			img = img[:22] + "..."
		}
		fmt.Fprintf(&b, "  %-20s %-25s %-15s\n", truncate(sp.Service, 20), img, sp.Class)
	}
	b.WriteString("\n")

	hasFindings := false
	for _, sp := range r.Services {
		if len(sp.Findings) > 0 {
			hasFindings = true
			break
		}
	}

	if hasFindings {
		b.WriteString("  Findings:\n")
		b.WriteString("  " + strings.Repeat("-", 60) + "\n")
		for _, sp := range r.Services {
			for _, f := range sp.Findings {
				sev := strings.ToUpper(f.Severity)
				if f.Line > 0 {
					fmt.Fprintf(&b, "  [%s] %s line %d: %s (%s)\n", sev, f.Service, f.Line, f.Detail, f.RuleID)
				} else {
					fmt.Fprintf(&b, "  [%s] %s: %s (%s)\n", sev, f.Service, f.Detail, f.RuleID)
				}
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
