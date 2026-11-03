package netalias

import (
	"encoding/json"
	"strings"
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

func svc(name string) compose.Service {
	return compose.Service{Name: name}
}

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/test"})
	if len(r.Services) != 0 {
		t.Fatalf("expected 0 services, got %d", len(r.Services))
	}
}

func TestCleanService(t *testing.T) {
	s := svc("web")
	c := collected([]compose.Service{s}, map[string]compose.Network{"app": {Internal: true}})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Fatalf("expected 0 findings for clean service, got %d", len(r.Services[0].Findings))
	}
}

func TestNetworkModeHost(t *testing.T) {
	s := svc("api")
	s.NetworkMode = "host"
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "network_mode_host" {
			found = true
			if f.Level != "high" {
				t.Fatalf("expected high, got %s", f.Level)
			}
		}
	}
	if !found {
		t.Fatal("expected network_mode_host finding")
	}
}

func TestNetworkModeContainer(t *testing.T) {
	s := svc("sidecar")
	s.NetworkMode = "container:main"
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "network_mode_container" {
			found = true
			if !strings.Contains(f.Message, "main") {
				t.Fatalf("expected container name in message")
			}
		}
	}
	if !found {
		t.Fatal("expected network_mode_container finding")
	}
}

func TestDefaultNetworkShared(t *testing.T) {
	s := svc("app")
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "default_network_shared" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected default_network_shared finding when no networks defined")
	}
}

func TestNoDefaultFindingWithCustomNetworks(t *testing.T) {
	s := svc("app")
	nets := map[string]compose.Network{"custom": {Internal: true}}
	c := collected([]compose.Service{s}, nets)
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Rule == "default_network_shared" {
			t.Fatal("should not flag default_network_shared when custom networks exist")
		}
	}
}

func TestExposedOnNonInternal(t *testing.T) {
	s := svc("web")
	s.Ports = []compose.PortMapping{{HostPort: 8080, TargetPort: 80}}
	nets := map[string]compose.Network{"frontend": {Internal: false}}
	c := collected([]compose.Service{s}, nets)
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "exposed_on_non_internal" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected exposed_on_non_internal finding")
	}
}

func TestNoExposeFindingOnInternalNetwork(t *testing.T) {
	s := svc("web")
	s.Ports = []compose.PortMapping{{HostPort: 8080, TargetPort: 80}}
	nets := map[string]compose.Network{"backend": {Internal: true}}
	c := collected([]compose.Service{s}, nets)
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Rule == "exposed_on_non_internal" {
			t.Fatal("should not flag when all networks are internal")
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	s1 := svc("a")
	s1.NetworkMode = "host"
	s2 := svc("b")
	s2.NetworkMode = "container:a"
	c := collected([]compose.Service{s1, s2}, nil)
	r := Analyze(c)
	if r.Summary.HostNetwork != 1 {
		t.Fatalf("expected 1 host_network, got %d", r.Summary.HostNetwork)
	}
	if r.Summary.ContainerNetwork != 1 {
		t.Fatalf("expected 1 container_network, got %d", r.Summary.ContainerNetwork)
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("a")
	s2 := svc("b")
	c := collected([]compose.Service{s1, s2}, nil)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatTextEmpty(t *testing.T) {
	text := FormatText(Report{})
	if !strings.Contains(text, "0 services") {
		t.Fatalf("expected '0 services' in output")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	r := Report{
		Services: []ServiceResult{{
			Service: "test",
			File:    "compose.yml",
			Findings: []Finding{{Level: "high", Rule: "network_mode_host", Message: "test msg"}},
		}},
		Summary: Summary{TotalServices: 1, TotalFindings: 1, HostNetwork: 1},
	}
	text := FormatText(r)
	if !strings.Contains(text, "test msg") {
		t.Fatalf("expected finding message in output")
	}
}

func TestFormatJSON(t *testing.T) {
	r := Report{Services: []ServiceResult{{Service: "x", File: "f"}}}
	data := FormatJSON(r)
	var parsed Report
	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.Services[0].Service != "x" {
		t.Fatalf("roundtrip failed")
	}
}
