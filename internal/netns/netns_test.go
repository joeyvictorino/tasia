package netns

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestAnalyzeCleanService(t *testing.T) {
	c := mkCollected(compose.Service{Name: "app"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyzeHostNetwork(t *testing.T) {
	c := mkCollected(compose.Service{Name: "svc", NetworkMode: "host"})
	r := Analyze(c)
	if r.Summary.HostNetwork != 1 {
		t.Errorf("expected 1 host network, got %d", r.Summary.HostNetwork)
	}
	f := r.Services[0].Findings[0]
	if f.RuleID != "netns_host_network" {
		t.Errorf("expected netns_host_network, got %s", f.RuleID)
	}
	if f.Severity != "critical" {
		t.Error("host network should be critical")
	}
}

func TestAnalyzeContainerNetwork(t *testing.T) {
	c := mkCollected(compose.Service{Name: "svc", NetworkMode: "container:nginx"})
	r := Analyze(c)
	if r.Summary.ContainerNetwork != 1 {
		t.Errorf("expected 1 container network, got %d", r.Summary.ContainerNetwork)
	}
	if !strings.Contains(r.Services[0].Findings[0].Detail, "nginx") {
		t.Error("expected target container name in detail")
	}
}

func TestAnalyzeServiceNetwork(t *testing.T) {
	c := mkCollected(compose.Service{Name: "svc", NetworkMode: "service:web"})
	r := Analyze(c)
	if r.Summary.ContainerNetwork != 1 {
		t.Errorf("expected 1 container network for service: mode, got %d", r.Summary.ContainerNetwork)
	}
	if !strings.Contains(r.Services[0].Findings[0].Detail, "web") {
		t.Error("expected target service name in detail")
	}
}

func TestAnalyzeNoNetwork(t *testing.T) {
	c := mkCollected(compose.Service{Name: "svc", NetworkMode: "none"})
	r := Analyze(c)
	if r.Summary.NoNetwork != 1 {
		t.Errorf("expected 1 no network, got %d", r.Summary.NoNetwork)
	}
	if r.Services[0].Findings[0].Severity != "medium" {
		t.Error("no network should be medium severity")
	}
}

func TestAnalyzeBridgeNetworkClean(t *testing.T) {
	c := mkCollected(compose.Service{Name: "svc", NetworkMode: "bridge"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("bridge network should have 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyzeMultipleServices(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "a", NetworkMode: "host"},
		compose.Service{Name: "b", NetworkMode: "container:a"},
		compose.Service{Name: "c"},
	)
	r := Analyze(c)
	if r.Summary.TotalFindings != 2 {
		t.Errorf("expected 2 findings, got %d", r.Summary.TotalFindings)
	}
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{Name: "svc", NetworkMode: "host"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Network Namespace") {
		t.Error("missing header")
	}
	if !strings.Contains(text, "netns_host_network") {
		t.Error("missing rule ID")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := mkCollected(compose.Service{Name: "clean"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Total findings:       0") {
		t.Error("expected 0 findings in output")
	}
}
