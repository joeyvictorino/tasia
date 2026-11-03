package composenet

import (
	"encoding/json"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services []compose.Service, networks map[string]compose.Network) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services, Networks: networks},
		},
	}
}

func hasRule(sr ServiceResult, rule string) bool {
	for _, f := range sr.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestHostNetwork(t *testing.T) {
	c := collected([]compose.Service{
		{Name: "web", NetworkMode: "host"},
	}, nil)
	r := Analyze(c)
	if !hasRule(r.Services[0], "composenet_host_network") {
		t.Error("expected composenet_host_network for network_mode: host")
	}
	if r.Summary.HostNetwork != 1 {
		t.Errorf("expected 1 host network, got %d", r.Summary.HostNetwork)
	}
}

func TestNoNetworkDefined(t *testing.T) {
	c := collected([]compose.Service{
		{Name: "app"},
	}, nil)
	r := Analyze(c)
	if !hasRule(r.Services[0], "composenet_no_network") {
		t.Error("expected composenet_no_network when no networks defined")
	}
	if r.Summary.NoNetworkDefined != 1 {
		t.Errorf("expected 1 no-network finding, got %d", r.Summary.NoNetworkDefined)
	}
}

func TestWithCustomNetwork(t *testing.T) {
	nets := map[string]compose.Network{
		"backend": {Internal: true},
	}
	c := collected([]compose.Service{
		{Name: "api"},
	}, nets)
	r := Analyze(c)
	if hasRule(r.Services[0], "composenet_no_network") {
		t.Error("should not flag when custom networks are defined")
	}
}

func TestDefaultBridge(t *testing.T) {
	c := collected([]compose.Service{
		{Name: "db", NetworkMode: "bridge"},
	}, nil)
	r := Analyze(c)
	if !hasRule(r.Services[0], "composenet_default_bridge") {
		t.Error("expected composenet_default_bridge for explicit bridge mode")
	}
	if r.Summary.DefaultBridge != 1 {
		t.Errorf("expected 1 default bridge, got %d", r.Summary.DefaultBridge)
	}
}

func TestHostWithPorts(t *testing.T) {
	c := collected([]compose.Service{
		{
			Name:        "web",
			NetworkMode: "host",
			Ports:       []compose.PortMapping{{HostPort: 8080, TargetPort: 80}},
		},
	}, nil)
	r := Analyze(c)
	if !hasRule(r.Services[0], "composenet_host_ports_redundant") {
		t.Error("expected composenet_host_ports_redundant for host mode with ports")
	}
}

func TestHostWithoutPorts(t *testing.T) {
	c := collected([]compose.Service{
		{Name: "worker", NetworkMode: "host"},
	}, nil)
	r := Analyze(c)
	if hasRule(r.Services[0], "composenet_host_ports_redundant") {
		t.Error("should not flag host_ports_redundant without ports")
	}
}

func TestCleanService(t *testing.T) {
	nets := map[string]compose.Network{
		"app-net": {},
	}
	c := collected([]compose.Service{
		{Name: "clean"},
	}, nets)
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Services[0].Findings))
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleServices(t *testing.T) {
	c := collected([]compose.Service{
		{Name: "web", NetworkMode: "host"},
		{Name: "api"},
	}, nil)
	r := Analyze(c)
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	c := collected([]compose.Service{
		{Name: "web", NetworkMode: "host"},
	}, nil)
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected([]compose.Service{
		{Name: "web", NetworkMode: "host"},
	}, nil)
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var r2 Report
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if r2.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service, got %d", r2.Summary.TotalServices)
	}
}

func TestNetworkModeNone(t *testing.T) {
	c := collected([]compose.Service{
		{Name: "isolated", NetworkMode: "none"},
	}, nil)
	r := Analyze(c)
	if hasRule(r.Services[0], "composenet_host_network") {
		t.Error("should not flag network_mode: none as host network")
	}
}
