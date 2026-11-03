package macvlan

import (
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
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestCleanService(t *testing.T) {
	s := svc("web")
	s.NetworkMode = "bridge"
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	for _, sr := range r.Services {
		if len(sr.Findings) > 0 {
			t.Fatal("clean bridge service should have no findings")
		}
	}
}

func TestMacvlanNetworkMode(t *testing.T) {
	s := svc("gateway")
	s.NetworkMode = "macvlan"
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "macvlan_network_mode" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected macvlan_network_mode finding")
	}
}

func TestIpvlanNetworkMode(t *testing.T) {
	s := svc("gateway")
	s.NetworkMode = "ipvlan"
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "macvlan_network_mode" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected macvlan_network_mode finding for ipvlan")
	}
}

func TestDirectHostAccess(t *testing.T) {
	s := svc("router")
	s.NetworkMode = "macvlan"
	s.Environment = []string{"PARENT=eth0"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "direct_host_access" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected direct_host_access finding")
	}
}

func TestPromiscuousMode(t *testing.T) {
	s := svc("sniffer")
	s.Environment = []string{"IFF_PROMISC=1"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "promiscuous_mode" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected promiscuous_mode finding")
	}
}

func TestMissingVlanTag(t *testing.T) {
	s := svc("node")
	s.NetworkMode = "macvlan"
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_vlan_tag" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected missing_vlan_tag finding")
	}
}

func TestVlanTagPresent(t *testing.T) {
	s := svc("node")
	s.NetworkMode = "macvlan"
	s.Environment = []string{"VLAN_ID=100"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_vlan_tag" {
				t.Fatal("should not flag missing vlan tag when configured")
			}
		}
	}
}

func TestMacvlanDangerousCap(t *testing.T) {
	s := svc("attacker")
	s.NetworkMode = "macvlan"
	s.CapAdd = []string{"NET_RAW"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "macvlan_dangerous_cap" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected macvlan_dangerous_cap finding")
	}
}

func TestMacvlanNetAdminCap(t *testing.T) {
	s := svc("admin")
	s.NetworkMode = "ipvlan"
	s.CapAdd = []string{"NET_ADMIN"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "macvlan_dangerous_cap" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected macvlan_dangerous_cap finding for NET_ADMIN")
	}
}

func TestMacvlanSysfsMountSysClassNet(t *testing.T) {
	s := svc("netmgr")
	s.NetworkMode = "macvlan"
	s.Volumes = []string{"/sys/class/net:/sys/class/net:ro"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "macvlan_sysfs_mount" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected macvlan_sysfs_mount finding")
	}
}

func TestMacvlanSysfsMountProcSysNet(t *testing.T) {
	s := svc("netmgr")
	s.NetworkMode = "macvlan"
	s.Volumes = []string{"/proc/sys/net:/host-net"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "macvlan_sysfs_mount" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected macvlan_sysfs_mount for proc/sys/net")
	}
}

func TestMacvlanNetworkDetected(t *testing.T) {
	nets := map[string]compose.Network{
		"macvlan-net": {Internal: false},
	}
	c := collected(nil, nets)
	r := Analyze(c)
	found := false
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "macvlan_network_detected" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected macvlan_network_detected finding")
	}
}

func TestMacvlanBroadcastExposure(t *testing.T) {
	nets := map[string]compose.Network{
		"macvlan-ext": {Internal: false},
	}
	c := collected(nil, nets)
	r := Analyze(c)
	found := false
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "macvlan_broadcast_exposure" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected macvlan_broadcast_exposure finding")
	}
}

func TestMacvlanInternalNoExposure(t *testing.T) {
	nets := map[string]compose.Network{
		"macvlan-internal": {Internal: true},
	}
	c := collected(nil, nets)
	r := Analyze(c)
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "macvlan_broadcast_exposure" {
				t.Fatal("internal macvlan should not trigger broadcast exposure")
			}
		}
	}
}

func TestIpvlanNetworkDetected(t *testing.T) {
	nets := map[string]compose.Network{
		"ipvlan-backend": {Internal: false},
	}
	c := collected(nil, nets)
	r := Analyze(c)
	found := false
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "ipvlan_network_detected" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected ipvlan_network_detected finding")
	}
}

func TestIpvlanBroadcastExposure(t *testing.T) {
	nets := map[string]compose.Network{
		"ipvlan-net": {Internal: false},
	}
	c := collected(nil, nets)
	r := Analyze(c)
	found := false
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "ipvlan_broadcast_exposure" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected ipvlan_broadcast_exposure finding")
	}
}

func TestSummaryCounts(t *testing.T) {
	s := svc("router")
	s.NetworkMode = "macvlan"
	s.Environment = []string{"IFF_PROMISC=1"}
	nets := map[string]compose.Network{
		"macvlan-net": {Internal: false},
	}
	c := collected([]compose.Service{s}, nets)
	r := Analyze(c)
	if r.Summary.PromiscuousMode < 1 {
		t.Fatal("expected promiscuous mode count > 0")
	}
	if r.Summary.MacvlanDrivers < 1 {
		t.Fatal("expected macvlan driver count > 0")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text")
	}
	if !strings.Contains(text, "0 findings") {
		t.Fatal("expected 0 findings in text")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	s := svc("gateway")
	s.NetworkMode = "macvlan"
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "gateway") {
		t.Fatal("expected service name in output")
	}
	if !strings.Contains(text, "Macvlan") {
		t.Fatal("expected Macvlan header")
	}
}

func TestIsMacvlanRelated(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"macvlan", true},
		{"ipvlan-net", true},
		{"bridge", false},
		{"host", false},
		{"my-macvlan-network", true},
	}
	for _, tt := range tests {
		if got := isMacvlanRelated(tt.name); got != tt.want {
			t.Errorf("isMacvlanRelated(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("macvlan-svc")
	s1.NetworkMode = "macvlan"
	s2 := svc("bridge-svc")
	s2.NetworkMode = "bridge"
	c := collected([]compose.Service{s1, s2}, nil)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestCapWithoutMacvlanNoFinding(t *testing.T) {
	s := svc("normal")
	s.NetworkMode = "bridge"
	s.CapAdd = []string{"NET_RAW"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "macvlan_dangerous_cap" {
				t.Fatal("NET_RAW without macvlan should not trigger macvlan_dangerous_cap")
			}
		}
	}
}
