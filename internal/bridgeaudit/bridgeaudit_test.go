package bridgeaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path:     "docker-compose.yml",
			Services: services,
		}},
	}
}

func collectedWithNetworks(nets map[string]compose.Network, services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path:     "docker-compose.yml",
			Services: services,
			Networks: nets,
		}},
	}
}

func svc(name string) compose.Service {
	return compose.Service{Name: name}
}

func findByRule(services []ServiceResult, rule string) []Finding {
	var found []Finding
	for _, sr := range services {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				found = append(found, f)
			}
		}
	}
	return found
}

func TestDefaultBridgeDetection(t *testing.T) {
	r := Analyze(collected(svc("web")))
	findings := findByRule(r.Services, "default_bridge_network")
	if len(findings) == 0 {
		t.Fatal("expected default_bridge_network finding for service with no network_mode")
	}
}

func TestExplicitBridgeMode(t *testing.T) {
	s := compose.Service{Name: "api", NetworkMode: "bridge"}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "default_bridge_network")
	if len(findings) == 0 {
		t.Fatal("expected default_bridge_network finding for network_mode: bridge")
	}
}

func TestHostModeNoDefaultBridge(t *testing.T) {
	s := compose.Service{Name: "proxy", NetworkMode: "host"}
	r := Analyze(collected(s))
	bridgeFindings := findByRule(r.Services, "default_bridge_network")
	if len(bridgeFindings) != 0 {
		t.Fatal("host mode service should not get default_bridge_network finding")
	}
	hostFindings := findByRule(r.Services, "unrestricted_container_comm")
	if len(hostFindings) == 0 {
		t.Fatal("expected unrestricted_container_comm finding for host network mode")
	}
}

func TestICCIsolationMultipleServices(t *testing.T) {
	r := Analyze(collected(svc("web"), svc("db"), svc("cache")))
	findings := findByRule(r.Services, "missing_icc_isolation")
	if len(findings) != 3 {
		t.Fatalf("expected 3 missing_icc_isolation findings for 3 services on default bridge, got %d", len(findings))
	}
}

func TestICCIsolationSingleService(t *testing.T) {
	r := Analyze(collected(svc("solo")))
	findings := findByRule(r.Services, "missing_icc_isolation")
	if len(findings) != 0 {
		t.Fatal("single service on default bridge should not get ICC finding")
	}
}

func TestPrivilegedOnBridge(t *testing.T) {
	s := compose.Service{Name: "agent", Privileged: true}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "privileged_on_bridge")
	if len(findings) == 0 {
		t.Fatal("expected privileged_on_bridge finding")
	}
	if findings[0].Level != "critical" {
		t.Fatalf("expected critical level, got %s", findings[0].Level)
	}
}

func TestPrivilegedHostModeNoBridgeFinding(t *testing.T) {
	s := compose.Service{Name: "agent", Privileged: true, NetworkMode: "host"}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "privileged_on_bridge")
	if len(findings) != 0 {
		t.Fatal("privileged container on host network should not get privileged_on_bridge finding")
	}
}

func TestNetAdminCapability(t *testing.T) {
	s := compose.Service{Name: "scanner", CapAdd: []string{"NET_ADMIN"}}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unrestricted_container_comm")
	if len(findings) == 0 {
		t.Fatal("expected unrestricted_container_comm finding for NET_ADMIN cap")
	}
}

func TestNetRawCapability(t *testing.T) {
	s := compose.Service{Name: "sniffer", CapAdd: []string{"NET_RAW"}}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unrestricted_container_comm")
	if len(findings) == 0 {
		t.Fatal("expected unrestricted_container_comm finding for NET_RAW cap")
	}
}

func TestAllCapability(t *testing.T) {
	s := compose.Service{Name: "root", CapAdd: []string{"ALL"}}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unrestricted_container_comm")
	if len(findings) == 0 {
		t.Fatal("expected unrestricted_container_comm for ALL capability")
	}
}

func TestNoNetworkSegmentation(t *testing.T) {
	r := Analyze(collected(svc("web")))
	findings := findByRule(r.Services, "no_network_segmentation")
	if len(findings) == 0 {
		t.Fatal("expected no_network_segmentation when no user-defined networks")
	}
}

func TestUserDefinedNetworkSuppressesSegmentation(t *testing.T) {
	nets := map[string]compose.Network{
		"frontend": {Internal: false},
	}
	r := Analyze(collectedWithNetworks(nets, svc("web")))
	findings := findByRule(r.Services, "no_network_segmentation")
	if len(findings) != 0 {
		t.Fatal("user-defined network should suppress no_network_segmentation finding")
	}
}

func TestInternalNetworkSuppressesSegmentation(t *testing.T) {
	nets := map[string]compose.Network{
		"backend": {Internal: true},
	}
	r := Analyze(collectedWithNetworks(nets, svc("web")))
	findings := findByRule(r.Services, "no_network_segmentation")
	if len(findings) != 0 {
		t.Fatal("internal network should suppress no_network_segmentation finding")
	}
}

func TestCleanServiceNoFindings(t *testing.T) {
	nets := map[string]compose.Network{
		"private": {Internal: true},
	}
	s := compose.Service{Name: "worker", NetworkMode: "none"}
	r := Analyze(collectedWithNetworks(nets, s))
	for _, sr := range r.Services {
		if len(sr.Findings) != 0 {
			t.Fatalf("network_mode: none with internal network should have no findings, got %d", len(sr.Findings))
		}
	}
}

func TestSummaryCountsCorrect(t *testing.T) {
	s1 := compose.Service{Name: "web", Privileged: true}
	s2 := compose.Service{Name: "db"}
	r := Analyze(collected(s1, s2))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 total services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.PrivilegedOnBridge != 1 {
		t.Fatalf("expected 1 privileged_on_bridge, got %d", r.Summary.PrivilegedOnBridge)
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Analyze(collected(svc("web")))
	text := FormatText(r)
	if !strings.Contains(text, "Bridge Network Security Audit") {
		t.Fatal("FormatText missing header")
	}
	if !strings.Contains(text, "web") {
		t.Fatal("FormatText missing service name")
	}
}

func TestNetCapOnNonBridgeNoFinding(t *testing.T) {
	s := compose.Service{Name: "scanner", NetworkMode: "none", CapAdd: []string{"NET_ADMIN"}}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unrestricted_container_comm")
	if len(findings) != 0 {
		t.Fatal("NET_ADMIN on network_mode:none should not produce unrestricted_container_comm finding")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := &collect.Collected{
		Root: "/multi",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: []compose.Service{svc("web")}},
			{Path: "docker-compose.dev.yml", Services: []compose.Service{svc("debug")}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services across files, got %d", r.Summary.TotalServices)
	}
}
