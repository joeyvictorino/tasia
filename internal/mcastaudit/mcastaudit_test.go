package mcastaudit

import (
	"fmt"
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

func TestNetAdminMulticast(t *testing.T) {
	s := compose.Service{Name: "scanner", CapAdd: []string{"NET_ADMIN"}}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unrestricted_multicast")
	if len(findings) == 0 {
		t.Fatal("expected unrestricted_multicast finding for NET_ADMIN")
	}
}

func TestNetRawMulticast(t *testing.T) {
	s := compose.Service{Name: "probe", CapAdd: []string{"NET_RAW"}}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unrestricted_multicast")
	if len(findings) == 0 {
		t.Fatal("expected unrestricted_multicast finding for NET_RAW")
	}
}

func TestAllCapMulticast(t *testing.T) {
	s := compose.Service{Name: "root", CapAdd: []string{"ALL"}}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unrestricted_multicast")
	if len(findings) == 0 {
		t.Fatal("expected unrestricted_multicast for ALL capability")
	}
}

func TestPrivilegedMulticast(t *testing.T) {
	s := compose.Service{Name: "agent", Privileged: true}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unrestricted_multicast")
	if len(findings) == 0 {
		t.Fatal("expected unrestricted_multicast for privileged container")
	}
}

func TestNoneBridgeNoMulticast(t *testing.T) {
	s := compose.Service{Name: "isolated", NetworkMode: "none", CapAdd: []string{"NET_ADMIN"}}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "unrestricted_multicast")
	if len(findings) != 0 {
		t.Fatal("network_mode: none should not get multicast findings")
	}
}

func TestHostModeExcessiveBroadcast(t *testing.T) {
	s := compose.Service{Name: "proxy", NetworkMode: "host"}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "excessive_broadcast_domain")
	if len(findings) == 0 {
		t.Fatal("expected excessive_broadcast_domain for host mode")
	}
}

func TestMulticastSysctlDetection(t *testing.T) {
	s := compose.Service{
		Name:    "router",
		Sysctls: map[string]string{"net.ipv4.conf.all.mc_forwarding": "1"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_igmp_snooping")
	if len(findings) == 0 {
		t.Fatal("expected missing_igmp_snooping for mc_forwarding sysctl")
	}
}

func TestIGMPSysctlDetection(t *testing.T) {
	s := compose.Service{
		Name:    "gateway",
		Sysctls: map[string]string{"net.ipv4.igmp_max_memberships": "256"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_igmp_snooping")
	if len(findings) == 0 {
		t.Fatal("expected missing_igmp_snooping for igmp sysctl")
	}
}

func TestBroadcastStormRiskLargeDomain(t *testing.T) {
	services := make([]compose.Service, 7)
	for i := range services {
		services[i] = compose.Service{Name: fmt.Sprintf("svc%d", i)}
	}
	r := Analyze(collected(services...))
	findings := findByRule(r.Services, "broadcast_storm_risk")
	if len(findings) == 0 {
		t.Fatal("expected broadcast_storm_risk for >5 services on bridge")
	}
}

func TestBroadcastStormSmallDomainNoFinding(t *testing.T) {
	r := Analyze(collected(svc("a"), svc("b"), svc("c")))
	findings := findByRule(r.Services, "broadcast_storm_risk")
	if len(findings) != 0 {
		t.Fatal("3 services should not trigger broadcast_storm_risk")
	}
}

func TestMulticastEnvVarDetection(t *testing.T) {
	s := compose.Service{
		Name:        "streamer",
		Environment: []string{"MCAST_ADDR=239.1.1.1"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "multicast_capability")
	if len(findings) == 0 {
		t.Fatal("expected multicast_capability for env with multicast address")
	}
}

func TestBroadcastEnvVarDetection(t *testing.T) {
	s := compose.Service{
		Name:        "beacon",
		Environment: []string{"MODE=broadcast"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "multicast_capability")
	if len(findings) == 0 {
		t.Fatal("expected multicast_capability for env with broadcast keyword")
	}
}

func TestMulticastAddr224Detection(t *testing.T) {
	s := compose.Service{
		Name:        "video",
		Environment: []string{"STREAM=224.0.0.1:5000"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "multicast_capability")
	if len(findings) == 0 {
		t.Fatal("expected multicast_capability for 224.x.x.x address")
	}
}

func TestCleanServiceNoFindings(t *testing.T) {
	s := compose.Service{Name: "worker", NetworkMode: "none"}
	r := Analyze(collected(s))
	for _, sr := range r.Services {
		if len(sr.Findings) != 0 {
			t.Fatalf("network_mode:none service should have no findings, got %d", len(sr.Findings))
		}
	}
}

func TestSummaryCountsCorrect(t *testing.T) {
	s1 := compose.Service{Name: "agent", Privileged: true}
	s2 := compose.Service{Name: "proxy", NetworkMode: "host"}
	r := Analyze(collected(s1, s2))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 total services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.UnrestrictedMulticast < 1 {
		t.Fatal("expected at least 1 unrestricted_multicast")
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Analyze(collected(svc("web")))
	text := FormatText(r)
	if !strings.Contains(text, "Multicast/Broadcast Network Audit") {
		t.Fatal("FormatText missing header")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := &collect.Collected{
		Root: "/multi",
		ComposeFiles: []compose.File{
			{Path: "a.yml", Services: []compose.Service{svc("web")}},
			{Path: "b.yml", Services: []compose.Service{svc("api")}},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestNonMulticastSysctlIgnored(t *testing.T) {
	s := compose.Service{
		Name:    "web",
		Sysctls: map[string]string{"net.core.somaxconn": "1024"},
	}
	r := Analyze(collected(s))
	findings := findByRule(r.Services, "missing_igmp_snooping")
	if len(findings) != 0 {
		t.Fatal("non-multicast sysctl should not trigger missing_igmp_snooping")
	}
}
