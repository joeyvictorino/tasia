package netaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(svcs []compose.Service, nets map[string]compose.Network) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs, Networks: nets}},
	}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestNoIssues(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 80, HostIP: "127.0.0.1"}}, ReadOnly: true},
	}
	nets := map[string]compose.Network{"frontend": {}}
	r := Analyze(collected(svcs, nets))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestHostNetworkMode(t *testing.T) {
	svcs := []compose.Service{{Name: "agent", NetworkMode: "host"}}
	r := Analyze(collected(svcs, nil))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "net_host_mode" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected net_host_mode finding")
	}
}

func TestHostWithPorts(t *testing.T) {
	svcs := []compose.Service{
		{Name: "agent", NetworkMode: "host", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}},
	}
	r := Analyze(collected(svcs, nil))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "net_host_with_ports" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected net_host_with_ports finding")
	}
}

func TestPrivilegedNetworkAccess(t *testing.T) {
	svcs := []compose.Service{{Name: "agent", Privileged: true}}
	r := Analyze(collected(svcs, nil))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "net_privileged_network" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected net_privileged_network finding")
	}
}

func TestDefaultBridge(t *testing.T) {
	svcs := []compose.Service{{Name: "web"}}
	r := Analyze(collected(svcs, nil))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "net_default_bridge" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected net_default_bridge finding")
	}
}

func TestNamedNetworksNoDefaultBridge(t *testing.T) {
	svcs := []compose.Service{{Name: "web"}}
	nets := map[string]compose.Network{"backend": {}}
	r := Analyze(collected(svcs, nets))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "net_default_bridge" {
				t.Fatal("should not flag default bridge when named networks exist")
			}
		}
	}
}

func TestPublicWritable(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Ports: []compose.PortMapping{{HostPort: 443, TargetPort: 443}}, ReadOnly: false},
	}
	nets := map[string]compose.Network{"net": {}}
	r := Analyze(collected(svcs, nets))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "net_public_writable" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected net_public_writable finding")
	}
}

func TestWideBind(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 80, HostIP: ""}}},
	}
	nets := map[string]compose.Network{"net": {}}
	r := Analyze(collected(svcs, nets))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "net_wide_bind" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected net_wide_bind finding")
	}
}

func TestLocalhostBindOK(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 80, HostIP: "127.0.0.1"}}, ReadOnly: true},
	}
	nets := map[string]compose.Network{"net": {}}
	r := Analyze(collected(svcs, nets))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "net_wide_bind" {
				t.Fatal("should not flag localhost bind")
			}
		}
	}
}

func TestHostNetCount(t *testing.T) {
	svcs := []compose.Service{
		{Name: "a", NetworkMode: "host"},
		{Name: "b", NetworkMode: "host"},
		{Name: "c"},
	}
	r := Analyze(collected(svcs, nil))
	if r.Summary.WithHostNet != 2 {
		t.Fatalf("expected 2 host net services, got %d", r.Summary.WithHostNet)
	}
}

func TestPortsCount(t *testing.T) {
	svcs := []compose.Service{
		{Name: "a", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}},
		{Name: "b"},
	}
	r := Analyze(collected(svcs, nil))
	if r.Summary.WithPorts != 1 {
		t.Fatalf("expected 1 service with ports, got %d", r.Summary.WithPorts)
	}
}

func TestFormatText(t *testing.T) {
	svcs := []compose.Service{{Name: "agent", NetworkMode: "host"}}
	r := Analyze(collected(svcs, nil))
	text := FormatText(r)
	if !strings.Contains(text, "Network Configuration") {
		t.Fatal("expected header")
	}
	if !strings.Contains(text, "net_host_mode") {
		t.Fatal("expected finding in output")
	}
}

func TestNetworksDefined(t *testing.T) {
	nets := map[string]compose.Network{"front": {}, "back": {}}
	svcs := []compose.Service{{Name: "web"}}
	r := Analyze(collected(svcs, nets))
	if r.Summary.NetworksDefined != 2 {
		t.Fatalf("expected 2 networks, got %d", r.Summary.NetworksDefined)
	}
}
