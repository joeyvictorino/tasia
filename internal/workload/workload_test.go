package workload

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func col(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}},
	}
}

func TestEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestClassifyDatabase(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "db", Image: "postgres:15"}))
	if r.Services[0].Class != ClassDatabase {
		t.Fatalf("expected database, got %s", r.Services[0].Class)
	}
}

func TestClassifyCache(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "cache", Image: "redis:7-alpine"}))
	if r.Services[0].Class != ClassCache {
		t.Fatalf("expected cache, got %s", r.Services[0].Class)
	}
}

func TestClassifyAIModel(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "llm", Image: "ollama/ollama:latest"}))
	if r.Services[0].Class != ClassAIModel {
		t.Fatalf("expected ai-model, got %s", r.Services[0].Class)
	}
}

func TestClassifyAgentRuntime(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "agent", Image: "n8nio/n8n:latest"}))
	if r.Services[0].Class != ClassAgentRuntime {
		t.Fatalf("expected agent-runtime, got %s", r.Services[0].Class)
	}
}

func TestClassifyVectorDB(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "vectors", Image: "chromadb/chroma:latest"}))
	if r.Services[0].Class != ClassVectorDB {
		t.Fatalf("expected vector-db, got %s", r.Services[0].Class)
	}
}

func TestClassifyReverseProxy(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "proxy", Image: "nginx:alpine"}))
	if r.Services[0].Class != ClassReverseProxy {
		t.Fatalf("expected reverse-proxy, got %s", r.Services[0].Class)
	}
}

func TestClassifyUnknown(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "custom", Image: "mycompany/myapp:v2"}))
	if r.Services[0].Class != ClassUnknown {
		t.Fatalf("expected unknown, got %s", r.Services[0].Class)
	}
	if r.Summary.Unclassified != 1 {
		t.Fatalf("expected 1 unclassified, got %d", r.Summary.Unclassified)
	}
}

func TestDBPrivilegedFinding(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "db", Image: "postgres:15", Privileged: true, PrivLine: 5}))
	found := false
	for _, sp := range r.Services {
		for _, f := range sp.Findings {
			if f.RuleID == "db_privileged" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected db_privileged finding")
	}
}

func TestAIPrivilegedFinding(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "llm", Image: "ollama/ollama", Privileged: true, PrivLine: 8}))
	found := false
	for _, sp := range r.Services {
		for _, f := range sp.Findings {
			if f.RuleID == "ai_privileged" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected ai_privileged finding")
	}
}

func TestAIHostNetwork(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "llm", Image: "ollama/ollama", NetworkMode: "host", NetworkModeLine: 7}))
	found := false
	for _, sp := range r.Services {
		for _, f := range sp.Findings {
			if f.RuleID == "ai_host_network" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected ai_host_network finding")
	}
}

func TestByClassSummary(t *testing.T) {
	r := Analyze(col(
		compose.Service{Name: "db", Image: "postgres:15"},
		compose.Service{Name: "cache", Image: "redis:7"},
		compose.Service{Name: "db2", Image: "mysql:8"},
	))
	if r.Summary.ByClass["database"] != 2 {
		t.Fatalf("expected 2 databases, got %d", r.Summary.ByClass["database"])
	}
	if r.Summary.ByClass["cache"] != 1 {
		t.Fatalf("expected 1 cache, got %d", r.Summary.ByClass["cache"])
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "llm", Image: "ollama/ollama"}))
	out := FormatText(r)
	if !strings.Contains(out, "Container Workload Classification") {
		t.Fatal("expected header")
	}
	if !strings.Contains(out, "ai-model") {
		t.Fatal("expected ai-model class in output")
	}
}

func TestMessageQueue(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "mq", Image: "rabbitmq:3-management"}))
	if r.Services[0].Class != ClassMessageQueue {
		t.Fatalf("expected message-queue, got %s", r.Services[0].Class)
	}
}
