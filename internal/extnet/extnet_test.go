package extnet

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
	if len(r.Networks) != 0 {
		t.Fatalf("expected 0 networks, got %d", len(r.Networks))
	}
}

func TestNoNetworksDefined(t *testing.T) {
	s1, s2 := svc("a"), svc("b")
	c := collected([]compose.Service{s1, s2}, nil)
	r := Analyze(c)
	found := false
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "no_networks_defined" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected no_networks_defined finding")
	}
}

func TestNoFindingForSingleService(t *testing.T) {
	s := svc("solo")
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "no_networks_defined" {
				t.Fatal("should not flag single-service compose file")
			}
		}
	}
}

func TestNetworkNotInternal(t *testing.T) {
	nets := map[string]compose.Network{"frontend": {Internal: false}}
	c := collected([]compose.Service{svc("web")}, nets)
	r := Analyze(c)
	found := false
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "network_not_internal" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected network_not_internal finding")
	}
}

func TestInternalNetworkClean(t *testing.T) {
	nets := map[string]compose.Network{"backend": {Internal: true}}
	c := collected([]compose.Service{svc("db")}, nets)
	r := Analyze(c)
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "network_not_internal" {
				t.Fatal("should not flag internal network")
			}
		}
	}
}

func TestBroadExternalNetwork(t *testing.T) {
	svcs := []compose.Service{svc("a"), svc("b"), svc("c"), svc("d")}
	nets := map[string]compose.Network{"app": {Internal: false}}
	c := collected(svcs, nets)
	r := Analyze(c)
	found := false
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "broad_external_network" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected broad_external_network finding for >3 services")
	}
}

func TestPrivilegedOnExternal(t *testing.T) {
	s := svc("agent")
	s.Privileged = true
	nets := map[string]compose.Network{"ext": {Internal: false}}
	c := collected([]compose.Service{s}, nets)
	r := Analyze(c)
	found := false
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "privileged_on_external" {
				found = true
				if f.Level != "high" {
					t.Fatalf("expected high, got %s", f.Level)
				}
			}
		}
	}
	if !found {
		t.Fatal("expected privileged_on_external finding")
	}
}

func TestSummaryCounts(t *testing.T) {
	nets := map[string]compose.Network{
		"ext1": {Internal: false},
		"int1": {Internal: true},
	}
	c := collected([]compose.Service{svc("a")}, nets)
	r := Analyze(c)
	if r.Summary.NonInternal != 1 {
		t.Fatalf("expected 1 non-internal, got %d", r.Summary.NonInternal)
	}
	if r.Summary.ServiceCount != 1 {
		t.Fatalf("expected 1 service, got %d", r.Summary.ServiceCount)
	}
}

func TestFormatTextEmpty(t *testing.T) {
	text := FormatText(Report{})
	if !strings.Contains(text, "0 networks") {
		t.Fatalf("expected '0 networks' in output")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	r := Report{
		Networks: []NetworkResult{{
			Network: "test",
			File:    "compose.yml",
			Findings: []Finding{{Level: "high", Rule: "privileged_on_external", Message: "test msg"}},
		}},
		Summary: Summary{TotalNetworks: 1, TotalFindings: 1},
	}
	text := FormatText(r)
	if !strings.Contains(text, "test msg") {
		t.Fatalf("expected finding message in output")
	}
}

func TestFormatJSON(t *testing.T) {
	r := Report{Networks: []NetworkResult{{Network: "x", File: "f"}}}
	data := FormatJSON(r)
	var parsed Report
	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.Networks[0].Network != "x" {
		t.Fatalf("roundtrip failed")
	}
}
