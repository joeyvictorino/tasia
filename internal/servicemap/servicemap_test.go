package servicemap

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeEmpty(t *testing.T) {
	sm := Analyze(&collect.Collected{})
	if sm.Stats.TotalServices != 0 {
		t.Errorf("empty input should have 0 services, got %d", sm.Stats.TotalServices)
	}
}

func TestAnalyzeSingleService(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx:1.25"},
				},
			},
		},
	}

	sm := Analyze(collected)
	if sm.Stats.TotalServices != 1 {
		t.Errorf("expected 1 service, got %d", sm.Stats.TotalServices)
	}
	if sm.Stats.Isolated != 1 {
		t.Errorf("single service should be isolated, got %d isolated", sm.Stats.Isolated)
	}
	if sm.Nodes[0].Image != "nginx:1.25" {
		t.Errorf("image = %q, want %q", sm.Nodes[0].Image, "nginx:1.25")
	}
}

func TestAnalyzeDependsOn(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:      "web",
						DependsOn: map[string]compose.DependsOnCondition{"db": {}},
					},
					{Name: "db"},
				},
			},
		},
	}

	sm := Analyze(collected)
	if sm.Stats.TotalEdges == 0 {
		t.Error("expected at least one edge from depends_on")
	}

	foundDep := false
	for _, e := range sm.Edges {
		if e.From == "web" && e.To == "db" && e.Type == "depends_on" {
			foundDep = true
		}
	}
	if !foundDep {
		t.Error("expected depends_on edge from web to db")
	}
	if sm.Stats.Isolated != 0 {
		t.Errorf("connected services should not be isolated, got %d", sm.Stats.Isolated)
	}
}

func TestAnalyzePorts(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name: "web",
						Ports: []compose.PortMapping{
							{HostPort: 8080, TargetPort: 80},
						},
					},
				},
			},
		},
	}

	sm := Analyze(collected)
	if len(sm.Nodes[0].Ports) != 1 {
		t.Errorf("expected 1 port, got %d", len(sm.Nodes[0].Ports))
	}
}

func TestFormatText(t *testing.T) {
	sm := ServiceMap{
		Nodes: []ServiceNode{
			{Name: "web", File: "compose.yml", Image: "nginx", Ports: []string{"80->80"}},
			{Name: "db", File: "compose.yml", Image: "postgres"},
		},
		Edges: []Edge{
			{From: "web", To: "db", Type: "depends_on"},
		},
		Stats: MapStats{TotalServices: 2, TotalEdges: 1},
	}

	text := FormatText(sm)
	if !strings.Contains(text, "Service Map") {
		t.Error("should contain header")
	}
	if !strings.Contains(text, "web") {
		t.Error("should contain service name")
	}
	if !strings.Contains(text, "depends_on") {
		t.Error("should contain edge type")
	}
}

func TestFormatDOT(t *testing.T) {
	sm := ServiceMap{
		Nodes: []ServiceNode{
			{Name: "web", Image: "nginx"},
			{Name: "db", Image: "postgres"},
		},
		Edges: []Edge{
			{From: "web", To: "db", Type: "depends_on"},
		},
	}

	dot := FormatDOT(sm)
	if !strings.Contains(dot, "digraph") {
		t.Error("should be a DOT graph")
	}
	if !strings.Contains(dot, "web") || !strings.Contains(dot, "db") {
		t.Error("should contain node names")
	}
}

func TestNodesSortedAlphabetically(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "compose.yml",
				Services: []compose.Service{
					{Name: "zebra"},
					{Name: "alpha"},
					{Name: "mid"},
				},
			},
		},
	}

	sm := Analyze(collected)
	if sm.Nodes[0].Name != "alpha" || sm.Nodes[2].Name != "zebra" {
		t.Error("nodes should be sorted alphabetically")
	}
}
