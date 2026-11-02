package netanalyze

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeEmpty(t *testing.T) {
	c := &collect.Collected{}
	a := AnalyzeNetworks(c)
	if a.Score != 100 {
		t.Errorf("empty should have score 100, got %.0f", a.Score)
	}
	if len(a.Findings) != 0 {
		t.Errorf("empty should have 0 findings, got %d", len(a.Findings))
	}
}

func TestAnalyzeHostMode(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "agent", NetworkMode: "host"},
			},
		}},
	}
	a := AnalyzeNetworks(c)
	if len(a.Findings) == 0 {
		t.Fatal("expected findings for host mode")
	}
	found := false
	for _, f := range a.Findings {
		if f.Severity == "high" && strings.Contains(f.Message, "host") {
			found = true
		}
	}
	if !found {
		t.Error("expected high severity finding for network_mode: host")
	}
}

func TestAnalyzeDefaultBridge(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "web"},
				{Name: "db"},
			},
		}},
	}
	a := AnalyzeNetworks(c)
	foundDefault := false
	for _, n := range a.Networks {
		if n.Name == "default" {
			foundDefault = true
			if len(n.Services) != 2 {
				t.Errorf("default network should have 2 services, got %d", len(n.Services))
			}
		}
	}
	if !foundDefault {
		t.Error("expected default network")
	}
}

func TestAnalyzeExplicitNetworks(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Networks: map[string]compose.Network{
				"frontend": {Internal: false},
				"backend":  {Internal: true},
			},
			Services: []compose.Service{
				{Name: "web"},
				{Name: "api"},
			},
		}},
	}
	a := AnalyzeNetworks(c)
	if len(a.Networks) == 0 {
		t.Error("expected networks in analysis")
	}
}

func TestAnalyzeConnections(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "svc1"},
				{Name: "svc2"},
				{Name: "svc3"},
			},
		}},
	}
	a := AnalyzeNetworks(c)
	if len(a.Connections) < 3 {
		t.Errorf("expected at least 3 connections for 3 services on default, got %d", len(a.Connections))
	}
}

func TestScoreDeduction(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "a", NetworkMode: "host"},
				{Name: "b", NetworkMode: "host"},
			},
		}},
	}
	a := AnalyzeNetworks(c)
	if a.Score >= 100 {
		t.Error("score should be reduced for host mode services")
	}
}

func TestScoreFloor(t *testing.T) {
	svcs := make([]compose.Service, 10)
	for i := range svcs {
		svcs[i] = compose.Service{Name: strings.Repeat("s", i+1), NetworkMode: "host"}
	}
	c := &collect.Collected{
		ComposeFiles: []compose.File{{Services: svcs}},
	}
	a := AnalyzeNetworks(c)
	if a.Score < 0 {
		t.Error("score should not go below 0")
	}
}

func TestFormatText(t *testing.T) {
	a := NetworkAnalysis{
		Score: 85,
		Networks: []NetworkInfo{
			{Name: "app", Services: []string{"web", "api"}, Internal: true},
		},
		Findings: []NetworkFinding{
			{Severity: "medium", Message: "test finding"},
		},
	}
	out := FormatText(a)
	if !strings.Contains(out, "85/100") {
		t.Error("expected score in text output")
	}
	if !strings.Contains(out, "app") {
		t.Error("expected network name in text output")
	}
	if !strings.Contains(out, "[MEDIUM]") {
		t.Error("expected finding severity in text output")
	}
}

func TestFormatDOT(t *testing.T) {
	a := NetworkAnalysis{
		Networks: []NetworkInfo{
			{Name: "backend", Services: []string{"api", "db"}, Internal: true},
		},
		Connections: []ServiceConnection{
			{From: "api", To: "db", Network: "backend"},
		},
	}
	out := FormatDOT(a)
	if !strings.Contains(out, "digraph") {
		t.Error("expected digraph in DOT output")
	}
	if !strings.Contains(out, "backend") {
		t.Error("expected network name in DOT output")
	}
	if !strings.Contains(out, "dashed") {
		t.Error("expected dashed style for internal network")
	}
}

func TestNoFindingsMessage(t *testing.T) {
	a := NetworkAnalysis{Score: 100}
	out := FormatText(a)
	if !strings.Contains(out, "No network security findings") {
		t.Error("expected no-findings message")
	}
}
