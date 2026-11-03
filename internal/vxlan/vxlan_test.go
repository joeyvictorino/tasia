package vxlan

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

func TestVxlanNoEncryption(t *testing.T) {
	s := svc("agent")
	s.NetworkMode = "overlay"
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "vxlan_no_encryption" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected vxlan_no_encryption finding")
	}
}

func TestVxlanWithEncryption(t *testing.T) {
	s := svc("agent")
	s.NetworkMode = "overlay"
	s.Environment = []string{"DOCKER_SWARM_ENCRYPT=true"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "vxlan_no_encryption" {
				t.Fatal("should not flag encryption when env enables it")
			}
		}
	}
}

func TestVxlanMissingVNI(t *testing.T) {
	s := svc("worker")
	s.NetworkMode = "vxlan-net"
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "vxlan_missing_vni" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected vxlan_missing_vni finding")
	}
}

func TestVxlanWithVNI(t *testing.T) {
	s := svc("worker")
	s.NetworkMode = "overlay"
	s.Environment = []string{"VXLAN_VNI=100", "ENCRYPT=true"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "vxlan_missing_vni" {
				t.Fatal("should not flag VNI when configured")
			}
		}
	}
}

func TestVxlanDefaultPort(t *testing.T) {
	s := svc("tunnel")
	s.Environment = []string{"VXLAN_PORT=4789"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "vxlan_default_port" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected vxlan_default_port finding")
	}
}

func TestVxlanBroadSubnet(t *testing.T) {
	s := svc("mesh")
	s.Environment = []string{"OVERLAY_SUBNET=10.0.0.0/8"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "vxlan_broad_subnet" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected vxlan_broad_subnet finding")
	}
}

func TestVxlanConfigMount(t *testing.T) {
	s := svc("network")
	s.Volumes = []string{"/etc/flannel:/etc/flannel:ro"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "vxlan_config_mount" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected vxlan_config_mount finding")
	}
}

func TestOverlayNetworkDetected(t *testing.T) {
	nets := map[string]compose.Network{
		"overlay-net": {Internal: false},
	}
	c := collected(nil, nets)
	r := Analyze(c)
	found := false
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "overlay_network_detected" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected overlay_network_detected finding")
	}
}

func TestOverlayNotInternal(t *testing.T) {
	nets := map[string]compose.Network{
		"vxlan-backend": {Internal: false},
	}
	c := collected(nil, nets)
	r := Analyze(c)
	found := false
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "overlay_not_internal" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected overlay_not_internal finding")
	}
}

func TestOverlayInternalNoFinding(t *testing.T) {
	nets := map[string]compose.Network{
		"overlay-internal": {Internal: true},
	}
	c := collected(nil, nets)
	r := Analyze(c)
	for _, nr := range r.Networks {
		for _, f := range nr.Findings {
			if f.Rule == "overlay_not_internal" {
				t.Fatal("internal overlay should not trigger overlay_not_internal")
			}
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	s := svc("agent")
	s.NetworkMode = "overlay"
	nets := map[string]compose.Network{
		"vxlan-net": {Internal: false},
	}
	c := collected([]compose.Service{s}, nets)
	r := Analyze(c)
	if r.Summary.MissingEncryption < 1 {
		t.Fatal("expected missing encryption count > 0")
	}
	if r.Summary.VxlanDrivers < 1 {
		t.Fatal("expected vxlan driver count > 0")
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
	s := svc("agent")
	s.NetworkMode = "overlay"
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "agent") {
		t.Fatal("expected service name in output")
	}
	if !strings.Contains(text, "VXLAN") {
		t.Fatal("expected VXLAN header")
	}
}

func TestIsVxlanRelated(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"overlay", true},
		{"vxlan-net", true},
		{"bridge", false},
		{"host", false},
		{"my-overlay-network", true},
	}
	for _, tt := range tests {
		if got := isVxlanRelated(tt.name); got != tt.want {
			t.Errorf("isVxlanRelated(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIsBroadSubnet(t *testing.T) {
	tests := []struct {
		subnet string
		want   bool
	}{
		{"10.0.0.0/8", true},
		{"172.16.0.0/12", true},
		{"192.168.1.0/24", false},
		{"10.0.0.0/16", true},
		{"0.0.0.0/0", true},
	}
	for _, tt := range tests {
		if got := isBroadSubnet(tt.subnet); got != tt.want {
			t.Errorf("isBroadSubnet(%q) = %v, want %v", tt.subnet, got, tt.want)
		}
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("overlay-svc")
	s1.NetworkMode = "overlay"
	s2 := svc("bridge-svc")
	s2.NetworkMode = "bridge"
	c := collected([]compose.Service{s1, s2}, nil)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestVtepVolume(t *testing.T) {
	s := svc("network")
	s.Volumes = []string{"/var/lib/vtep:/vtep"}
	c := collected([]compose.Service{s}, nil)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "vxlan_config_mount" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected vxlan_config_mount for vtep volume")
	}
}
