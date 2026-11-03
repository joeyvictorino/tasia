package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestBuildServiceGraphEmpty(t *testing.T) {
	g := buildServiceGraphFromFiles(nil)
	if len(g.Nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(g.Nodes))
	}
}

func TestBuildServiceGraphNodes(t *testing.T) {
	dir := t.TempDir()
	yml := `services:
  ollama:
    image: ollama/ollama
  webui:
    image: ghcr.io/open-webui/open-webui
  qdrant:
    image: qdrant/qdrant
`
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := compose.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	g := buildServiceGraphFromFiles([]compose.File{*f})

	if len(g.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(g.Nodes))
	}

	cats := map[string]string{}
	for _, n := range g.Nodes {
		cats[n.Name] = n.Category
	}
	if cats["ollama"] != "inference" {
		t.Errorf("ollama should be inference, got %s", cats["ollama"])
	}
	if cats["webui"] != "ui" {
		t.Errorf("webui should be ui, got %s", cats["webui"])
	}
	if cats["qdrant"] != "vector-db" {
		t.Errorf("qdrant should be vector-db, got %s", cats["qdrant"])
	}
}

func TestBuildServiceGraphSharedVolume(t *testing.T) {
	dir := t.TempDir()
	yml := `services:
  app:
    image: myapp
    volumes:
      - shared_data:/data
  worker:
    image: myworker
    volumes:
      - shared_data:/data
`
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := compose.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	g := buildServiceGraphFromFiles([]compose.File{*f})

	if len(g.Edges) != 1 {
		t.Fatalf("expected 1 edge for shared volume, got %d", len(g.Edges))
	}
	if g.Edges[0].Label != "vol:shared_data" {
		t.Errorf("edge label should be vol:shared_data, got %s", g.Edges[0].Label)
	}
}

func TestGraphToDOT(t *testing.T) {
	g := serviceGraph{
		Nodes: []graphNode{
			{Name: "ollama", Category: "inference"},
			{Name: "webui", Category: "ui"},
		},
		Edges: []graphEdge{
			{From: "webui", To: "ollama", Label: "vol:models"},
		},
	}

	dot := graphToDOT(g)
	if !strings.Contains(dot, "digraph stack") {
		t.Error("DOT output should start with digraph")
	}
	if !strings.Contains(dot, `"ollama"`) {
		t.Error("DOT should contain ollama node")
	}
	if !strings.Contains(dot, `"webui" -> "ollama"`) {
		t.Error("DOT should contain edge")
	}
	if !strings.Contains(dot, "fillcolor") {
		t.Error("DOT should have colored nodes")
	}
}

func TestGraphToMermaid(t *testing.T) {
	g := serviceGraph{
		Nodes: []graphNode{
			{Name: "redis", Category: "datastore"},
			{Name: "app", Category: "other"},
		},
		Edges: []graphEdge{
			{From: "app", To: "redis", Label: "vol:cache"},
		},
	}

	md := graphToMermaid(g)
	if !strings.Contains(md, "graph LR") {
		t.Error("Mermaid should start with graph LR")
	}
	if !strings.Contains(md, "redis") {
		t.Error("Mermaid should contain redis")
	}
	if !strings.Contains(md, "vol:cache") {
		t.Error("Mermaid should contain edge label")
	}
}

func TestGraphToText(t *testing.T) {
	g := serviceGraph{
		Nodes: []graphNode{
			{Name: "app", Category: "other"},
			{Name: "db", Category: "datastore"},
		},
		Edges: []graphEdge{
			{From: "app", To: "db", Label: "vol:data"},
		},
	}

	text := graphToText(g)
	if !strings.Contains(text, "Stack graph (2 services)") {
		t.Error("text output should show service count")
	}
	if !strings.Contains(text, "[datastore]") {
		t.Error("text output should show categories")
	}
	if !strings.Contains(text, "app <-> db") {
		t.Error("text output should show connections")
	}
}

func TestRunGraphDOT(t *testing.T) {
	dir := t.TempDir()
	yml := `services:
  app:
    image: myapp
  db:
    image: postgres:16
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runGraph([]string{"--path", dir, "--format", "dot"})
	if err != nil {
		t.Fatalf("runGraph dot failed: %v", err)
	}
}

func TestRunGraphMermaid(t *testing.T) {
	dir := t.TempDir()
	yml := `services:
  app:
    image: myapp
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runGraph([]string{"--path", dir, "--format", "mermaid"})
	if err != nil {
		t.Fatalf("runGraph mermaid failed: %v", err)
	}
}

func TestSanitizeMermaidID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"my-service", "my_service"},
		{"app.web", "app_web"},
		{"simple", "simple"},
	}
	for _, tt := range tests {
		got := sanitizeMermaidID(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeMermaidID(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
