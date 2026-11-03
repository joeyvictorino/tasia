package netfilter

import (
	"encoding/json"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func collectedWithNetworks(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services, Networks: map[string]compose.Network{"frontend": {}}},
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

func TestHostNetworkMode(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		NetworkMode: "host",
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "netfilter_host_network") {
		t.Error("expected netfilter_host_network for network_mode: host")
	}
	if r.Summary.HostNetworks != 1 {
		t.Errorf("expected 1 host network, got %d", r.Summary.HostNetworks)
	}
}

func TestUnrestrictedPorts(t *testing.T) {
	c := collected(compose.Service{
		Name: "web",
		Ports: []compose.PortMapping{
			{HostPort: 8080, TargetPort: 80, Raw: "8080:80"},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "netfilter_unrestricted_ports") {
		t.Error("expected netfilter_unrestricted_ports when no custom networks")
	}
	if r.Summary.UnrestrictedPorts != 1 {
		t.Errorf("expected 1 unrestricted port finding, got %d", r.Summary.UnrestrictedPorts)
	}
}

func TestPortsWithNetworksSafe(t *testing.T) {
	c := collectedWithNetworks(compose.Service{
		Name: "web",
		Ports: []compose.PortMapping{
			{HostPort: 8080, TargetPort: 80, Raw: "8080:80"},
		},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "netfilter_unrestricted_ports") {
		t.Error("should not flag unrestricted_ports when custom networks exist")
	}
}

func TestHostModeNoUnrestrictedPorts(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		NetworkMode: "host",
		Ports: []compose.PortMapping{
			{HostPort: 8080, TargetPort: 80, Raw: "8080:80"},
		},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "netfilter_unrestricted_ports") {
		t.Error("should not flag unrestricted_ports when network_mode is host")
	}
}

func TestAgentNoEgressControl(t *testing.T) {
	c := collected(compose.Service{
		Name:  "my-agent",
		Image: "langchain/agent:latest",
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "netfilter_no_egress_control") {
		t.Error("expected netfilter_no_egress_control for agent service without egress restriction")
	}
	if r.Summary.NoEgressControl != 1 {
		t.Errorf("expected 1 no egress control, got %d", r.Summary.NoEgressControl)
	}
}

func TestAgentWithNetworkNone(t *testing.T) {
	c := collected(compose.Service{
		Name:        "my-agent",
		Image:       "langchain/agent:latest",
		NetworkMode: "none",
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "netfilter_no_egress_control") {
		t.Error("should not flag no_egress_control when network_mode is none")
	}
}

func TestAgentWithNetworkPolicy(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{
				{Name: "my-agent", Image: "crewai/crew:latest"},
			}},
		},
		HasNetworkPolicy: true,
	}
	r := Analyze(c)
	if hasRule(r.Services[0], "netfilter_no_egress_control") {
		t.Error("should not flag no_egress_control when HasNetworkPolicy is true")
	}
}

func TestNonAgentNoEgressFlag(t *testing.T) {
	c := collected(compose.Service{
		Name:  "postgres",
		Image: "postgres:15",
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "netfilter_no_egress_control") {
		t.Error("should not flag no_egress_control for non-agent service")
	}
}

func TestAgentDetectedByRuntime(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{
				{Name: "worker", Image: "custom:latest"},
			}},
		},
		DetectedAgentRuntimes: []string{"worker"},
	}
	r := Analyze(c)
	if !hasRule(r.Services[0], "netfilter_no_egress_control") {
		t.Error("expected netfilter_no_egress_control for runtime-detected agent")
	}
}

func TestAgentDetectedByName(t *testing.T) {
	c := collected(compose.Service{
		Name:  "flowise-bot",
		Image: "ubuntu:22.04",
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "netfilter_no_egress_control") {
		t.Error("expected netfilter_no_egress_control for agent-named service")
	}
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{Name: "clean", Image: "nginx:latest"})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for clean service, got %d", len(r.Services[0].Findings))
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestPortWithoutHostPort(t *testing.T) {
	c := collected(compose.Service{
		Name: "app",
		Ports: []compose.PortMapping{
			{TargetPort: 3000, Raw: "3000"},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "netfilter_unrestricted_ports") {
		t.Error("expected netfilter_unrestricted_ports for container-only port without networks")
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		NetworkMode: "host",
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{
		Name:        "svc",
		NetworkMode: "host",
		Ports: []compose.PortMapping{
			{HostPort: 80, TargetPort: 80, Raw: "80:80"},
		},
	})
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
		t.Errorf("expected 1 service after round-trip, got %d", r2.Summary.TotalServices)
	}
}
