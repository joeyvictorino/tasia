package apiexpose

import (
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

func TestAnalyze_Empty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/empty"})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyze_NoFindings(t *testing.T) {
	svc := compose.Service{
		Name: "web",
		Ports: []compose.PortMapping{
			{HostIP: "127.0.0.1", HostPort: 8080, TargetPort: 8080, Raw: "127.0.0.1:8080:8080"},
		},
	}
	r := Analyze(collected(svc))
	for _, sr := range r.Services {
		if sr.Service == "web" {
			for _, f := range sr.Findings {
				if f.Rule == "apiexpose_wildcard_bind" {
					t.Fatal("should not flag 127.0.0.1 binding as wildcard")
				}
			}
		}
	}
}

func TestDockerAPIPort(t *testing.T) {
	svc := compose.Service{
		Name: "daemon",
		Ports: []compose.PortMapping{
			{HostPort: 2375, TargetPort: 2375, Raw: "2375:2375"},
		},
	}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "apiexpose_docker_api" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected apiexpose_docker_api finding")
	}
	if r.Summary.DockerAPI != 1 {
		t.Fatalf("expected DockerAPI=1, got %d", r.Summary.DockerAPI)
	}
}

func TestDockerAPITargetPort(t *testing.T) {
	svc := compose.Service{
		Name: "proxy",
		Ports: []compose.PortMapping{
			{HostPort: 9999, TargetPort: 2376, Raw: "9999:2376"},
		},
	}
	r := Analyze(collected(svc))
	if r.Summary.DockerAPI != 1 {
		t.Fatal("should detect Docker API on target port")
	}
}

func TestDebugPort_Node(t *testing.T) {
	svc := compose.Service{
		Name: "app",
		Ports: []compose.PortMapping{
			{HostPort: 9229, TargetPort: 9229, Raw: "9229:9229"},
		},
	}
	r := Analyze(collected(svc))
	if r.Summary.DebugPort != 1 {
		t.Fatal("expected debug port finding for Node.js 9229")
	}
}

func TestDebugPort_Java(t *testing.T) {
	svc := compose.Service{
		Name: "backend",
		Ports: []compose.PortMapping{
			{HostPort: 5005, TargetPort: 5005, Raw: "5005:5005"},
		},
	}
	r := Analyze(collected(svc))
	if r.Summary.DebugPort != 1 {
		t.Fatal("expected debug port finding for Java 5005")
	}
}

func TestDebugPort_GoDelve(t *testing.T) {
	svc := compose.Service{
		Name: "svc",
		Ports: []compose.PortMapping{
			{HostPort: 4000, TargetPort: 4000, Raw: "4000:4000"},
		},
	}
	r := Analyze(collected(svc))
	if r.Summary.DebugPort != 1 {
		t.Fatal("expected debug port finding for Go Delve 4000")
	}
}

func TestMgmtPort_Portainer(t *testing.T) {
	svc := compose.Service{
		Name: "portainer",
		Ports: []compose.PortMapping{
			{HostPort: 9000, TargetPort: 9000, Raw: "9000:9000"},
		},
	}
	r := Analyze(collected(svc))
	if r.Summary.MgmtPort != 1 {
		t.Fatal("expected mgmt port finding for Portainer 9000")
	}
}

func TestMgmtPort_Grafana(t *testing.T) {
	svc := compose.Service{
		Name: "grafana",
		Ports: []compose.PortMapping{
			{HostPort: 3000, TargetPort: 3000, Raw: "3000:3000"},
		},
	}
	r := Analyze(collected(svc))
	if r.Summary.MgmtPort != 1 {
		t.Fatal("expected mgmt port finding for Grafana 3000")
	}
}

func TestPrivilegedPort(t *testing.T) {
	svc := compose.Service{
		Name: "nginx",
		Ports: []compose.PortMapping{
			{HostIP: "127.0.0.1", HostPort: 80, TargetPort: 80, Raw: "127.0.0.1:80:80"},
		},
	}
	r := Analyze(collected(svc))
	if r.Summary.PrivilegedPort != 1 {
		t.Fatal("expected privileged port finding for port 80")
	}
}

func TestWildcardBind_EmptyIP(t *testing.T) {
	svc := compose.Service{
		Name: "api",
		Ports: []compose.PortMapping{
			{HostPort: 8080, TargetPort: 8080, Raw: "8080:8080"},
		},
	}
	r := Analyze(collected(svc))
	if r.Summary.WildcardBind != 1 {
		t.Fatal("expected wildcard bind finding for empty HostIP")
	}
}

func TestWildcardBind_Explicit(t *testing.T) {
	svc := compose.Service{
		Name: "api",
		Ports: []compose.PortMapping{
			{HostIP: "0.0.0.0", HostPort: 8080, TargetPort: 8080, Raw: "0.0.0.0:8080:8080"},
		},
	}
	r := Analyze(collected(svc))
	if r.Summary.WildcardBind != 1 {
		t.Fatal("expected wildcard bind finding for 0.0.0.0")
	}
}

func TestHostNetworkPorts(t *testing.T) {
	svc := compose.Service{
		Name:        "net",
		NetworkMode: "host",
		Ports: []compose.PortMapping{
			{HostPort: 8080, TargetPort: 8080, Raw: "8080:8080"},
		},
	}
	r := Analyze(collected(svc))
	if r.Summary.HostNetworkPorts != 1 {
		t.Fatal("expected host_network_ports finding")
	}
}

func TestHostNetworkNoPorts(t *testing.T) {
	svc := compose.Service{
		Name:        "net",
		NetworkMode: "host",
	}
	r := Analyze(collected(svc))
	if r.Summary.HostNetworkPorts != 0 {
		t.Fatal("should not flag host mode without ports")
	}
}

func TestMultipleFindings(t *testing.T) {
	svc := compose.Service{
		Name: "danger",
		Ports: []compose.PortMapping{
			{HostPort: 2375, TargetPort: 2375, Raw: "2375:2375"},
			{HostPort: 9229, TargetPort: 9229, Raw: "9229:9229"},
		},
	}
	r := Analyze(collected(svc))
	if r.Summary.TotalFindings < 2 {
		t.Fatalf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	svc := compose.Service{
		Name: "app",
		Ports: []compose.PortMapping{
			{HostPort: 2375, TargetPort: 2375, Raw: "2375:2375"},
		},
	}
	r := Analyze(collected(svc))
	text := FormatText(r)
	if text == "" {
		t.Fatal("FormatText returned empty")
	}
	if !contains(text, "API Exposure Audit") {
		t.Fatal("missing header")
	}
	if !contains(text, "Docker API") {
		t.Fatal("missing Docker API in output")
	}
}

func TestFormatText_NoFindings(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/empty"})
	text := FormatText(r)
	if !contains(text, "0 findings") {
		t.Fatal("should show 0 findings")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
