package egress

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.Score != 100 {
		t.Errorf("expected score 100, got %d", r.Summary.Score)
	}
}

func TestHostNetwork(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "agent", NetworkMode: "host"},
			},
		}},
	}
	r := Analyze(&c)
	if r.Summary.HostNetworkCount != 1 {
		t.Errorf("expected 1 host-network service, got %d", r.Summary.HostNetworkCount)
	}
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "egress_host_network" {
			found = true
		}
	}
	if !found {
		t.Error("expected egress_host_network finding")
	}
}

func TestPortAllInterfaces(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{
					Name: "web",
					Ports: []compose.PortMapping{
						{HostPort: 8080, TargetPort: 8080, Raw: "8080:8080"},
					},
				},
			},
		}},
	}
	r := Analyze(&c)
	if r.Summary.WideOpenPorts != 1 {
		t.Errorf("expected 1 wide-open port, got %d", r.Summary.WideOpenPorts)
	}
}

func TestPortLocalhost(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{
					Name: "web",
					Ports: []compose.PortMapping{
						{HostPort: 8080, TargetPort: 8080, HostIP: "127.0.0.1", Raw: "127.0.0.1:8080:8080"},
					},
				},
			},
		}},
	}
	r := Analyze(&c)
	if r.Summary.WideOpenPorts != 0 {
		t.Errorf("expected 0 wide-open ports, got %d", r.Summary.WideOpenPorts)
	}
}

func TestSensitivePortExposed(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{
					Name: "ollama",
					Ports: []compose.PortMapping{
						{HostPort: 11434, TargetPort: 11434, Raw: "11434:11434"},
					},
				},
			},
		}},
	}
	r := Analyze(&c)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "egress_sensitive_port_exposed" {
			found = true
		}
	}
	if !found {
		t.Error("expected egress_sensitive_port_exposed finding")
	}
}

func TestCustomDNS(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "agent", DNS: []string{"8.8.8.8", "8.8.4.4"}},
			},
		}},
	}
	r := Analyze(&c)
	if r.Summary.CustomDNSCount != 1 {
		t.Errorf("expected 1 custom DNS, got %d", r.Summary.CustomDNSCount)
	}
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "egress_custom_dns" {
			found = true
		}
	}
	if !found {
		t.Error("expected egress_custom_dns finding")
	}
}

func TestLocalDNSNoFinding(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "agent", DNS: []string{"127.0.0.11"}},
			},
		}},
	}
	r := Analyze(&c)
	for _, f := range r.Findings {
		if f.RuleID == "egress_custom_dns" {
			t.Error("should not flag localhost DNS")
		}
	}
}

func TestEgressRiskHigh(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{
					Name: "app",
					Ports: []compose.PortMapping{
						{HostPort: 80, TargetPort: 80, Raw: "80:80"},
						{HostPort: 443, TargetPort: 443, Raw: "443:443"},
						{HostPort: 8080, TargetPort: 8080, Raw: "8080:8080"},
						{HostPort: 9090, TargetPort: 9090, Raw: "9090:9090"},
					},
				},
			},
		}},
	}
	r := Analyze(&c)
	if len(r.Services) == 0 {
		t.Fatal("expected at least 1 service")
	}
	if r.Services[0].EgressRisk != "high" {
		t.Errorf("expected high risk, got %s", r.Services[0].EgressRisk)
	}
}

func TestEgressRiskLow(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "db", Ports: []compose.PortMapping{
					{HostPort: 5432, TargetPort: 5432, HostIP: "127.0.0.1", Raw: "127.0.0.1:5432:5432"},
				}},
			},
		}},
	}
	r := Analyze(&c)
	if r.Services[0].EgressRisk != "low" {
		t.Errorf("expected low risk, got %s", r.Services[0].EgressRisk)
	}
}

func TestDockerfileExposeSensitive(t *testing.T) {
	c := collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM python:3.11\nEXPOSE 8888",
				Exposes: []collect.DockerfileExpose{
					{Ports: "8888", Line: 2},
				},
			},
		},
	}
	r := Analyze(&c)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "egress_dockerfile_expose_sensitive" {
			found = true
		}
	}
	if !found {
		t.Error("expected egress_dockerfile_expose_sensitive finding")
	}
}

func TestScoreDegrades(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "a1", NetworkMode: "host"},
				{Name: "a2", DNS: []string{"8.8.8.8"}},
			},
		}},
	}
	r := Analyze(&c)
	if r.Summary.Score >= 100 {
		t.Errorf("expected degraded score, got %d", r.Summary.Score)
	}
}

func TestFormatText(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "web", Ports: []compose.PortMapping{
					{HostPort: 80, TargetPort: 80, Raw: "80:80"},
				}},
			},
		}},
	}
	r := Analyze(&c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text")
	}
	if !strings.Contains(text, "Network Egress") {
		t.Error("expected header in text")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "web", NetworkMode: "host"},
			},
		}},
	}
	r := Analyze(&c)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Summary.HostNetworkCount != 1 {
		t.Error("host network count mismatch after JSON round-trip")
	}
}

func TestMultipleServices(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "web", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80, Raw: "80:80"}}},
				{Name: "api", Ports: []compose.PortMapping{{HostPort: 3000, TargetPort: 3000, Raw: "3000:3000"}}},
				{Name: "db", Ports: []compose.PortMapping{{HostPort: 5432, TargetPort: 5432, HostIP: "127.0.0.1", Raw: "127.0.0.1:5432:5432"}}},
			},
		}},
	}
	r := Analyze(&c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WideOpenPorts != 2 {
		t.Errorf("expected 2 wide-open ports, got %d", r.Summary.WideOpenPorts)
	}
}
