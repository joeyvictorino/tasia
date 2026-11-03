package ipblock

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services []compose.Service, networks map[string]compose.Network) *collect.Collected {
	if networks == nil {
		networks = map[string]compose.Network{}
	}
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services, Networks: networks},
		},
	}
}

func TestEmptyServices(t *testing.T) {
	r := Analyze(collected(nil, nil))
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestWideOpenSensitive(t *testing.T) {
	svcs := []compose.Service{
		{Name: "postgres", Image: "postgres:15", Ports: []compose.PortMapping{
			{Raw: "0.0.0.0:5432:5432", HostIP: "0.0.0.0", HostPort: 5432, TargetPort: 5432},
		}},
	}
	r := Analyze(collected(svcs, nil))
	if r.Summary.WideOpenNetworks == 0 {
		t.Fatal("expected wide-open finding for postgres on 0.0.0.0")
	}
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "ipblock_wide_open" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected ipblock_wide_open rule")
	}
}

func TestNonSensitiveNoWideOpen(t *testing.T) {
	svcs := []compose.Service{
		{Name: "web-frontend", Image: "nginx:latest", Ports: []compose.PortMapping{
			{Raw: "0.0.0.0:80:80", HostIP: "0.0.0.0", HostPort: 80, TargetPort: 80},
		}},
	}
	r := Analyze(collected(svcs, nil))
	if r.Summary.WideOpenNetworks != 0 {
		t.Fatal("non-sensitive service should not trigger wide-open finding")
	}
}

func TestLoopbackBinding(t *testing.T) {
	svcs := []compose.Service{
		{Name: "redis", Image: "redis:7", Ports: []compose.PortMapping{
			{Raw: "127.0.0.1:6379:6379", HostIP: "127.0.0.1", HostPort: 6379, TargetPort: 6379},
		}},
	}
	r := Analyze(collected(svcs, nil))
	if r.Summary.LoopbackExposed == 0 {
		t.Fatal("expected loopback finding")
	}
}

func TestMissingIPRestrict(t *testing.T) {
	svcs := []compose.Service{
		{Name: "redis", Image: "redis:7", Ports: []compose.PortMapping{
			{Raw: "6379:6379", HostPort: 6379, TargetPort: 6379},
		}},
	}
	r := Analyze(collected(svcs, nil))
	if r.Summary.MissingIPRestrict == 0 {
		t.Fatal("expected missing IP restriction for sensitive service with ports")
	}
}

func TestHasIPRestriction(t *testing.T) {
	svcs := []compose.Service{
		{Name: "redis", Image: "redis:7", Ports: []compose.PortMapping{
			{Raw: "6379:6379", HostPort: 6379, TargetPort: 6379},
		}, Environment: []string{"ALLOWED_IPS=10.0.0.0/24"}},
	}
	r := Analyze(collected(svcs, nil))
	if r.Summary.MissingIPRestrict != 0 {
		t.Fatal("should not flag when IP restriction is present")
	}
}

func TestNoPortsNoMissingIPRestrict(t *testing.T) {
	svcs := []compose.Service{
		{Name: "redis", Image: "redis:7"},
	}
	r := Analyze(collected(svcs, nil))
	if r.Summary.MissingIPRestrict != 0 {
		t.Fatal("should not flag missing IP restriction when no ports exposed")
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Analyze(collected(nil, nil))
	text := FormatText(r)
	if !strings.Contains(text, "IP Block") {
		t.Fatal("expected header in text output")
	}
}

func TestFormatTextFindings(t *testing.T) {
	svcs := []compose.Service{
		{Name: "postgres", Image: "postgres:15", Ports: []compose.PortMapping{
			{Raw: "0.0.0.0:5432:5432", HostIP: "0.0.0.0", HostPort: 5432, TargetPort: 5432},
		}},
	}
	r := Analyze(collected(svcs, nil))
	text := FormatText(r)
	if !strings.Contains(text, "postgres") {
		t.Fatal("expected postgres in text output")
	}
}

func TestIsPrivateRange(t *testing.T) {
	if !isPrivateRange("10.0.0.0/8") {
		t.Fatal("10.0.0.0/8 should be private")
	}
	if !isPrivateRange("192.168.1.0/24") {
		t.Fatal("192.168.1.0/24 should be private")
	}
	if isPrivateRange("8.8.8.0/24") {
		t.Fatal("8.8.8.0/24 should not be private")
	}
}

func TestIsBroadCIDR(t *testing.T) {
	if !isBroadCIDR("10.0.0.0/8") {
		t.Fatal("/8 should be broad")
	}
	if isBroadCIDR("10.0.0.0/24") {
		t.Fatal("/24 should not be broad")
	}
}

func TestMultipleServices(t *testing.T) {
	svcs := []compose.Service{
		{Name: "postgres", Image: "postgres:15", Ports: []compose.PortMapping{
			{Raw: "0.0.0.0:5432:5432", HostIP: "0.0.0.0", HostPort: 5432, TargetPort: 5432},
		}},
		{Name: "redis", Image: "redis:7", Ports: []compose.PortMapping{
			{Raw: "6379:6379", HostPort: 6379, TargetPort: 6379},
		}},
		{Name: "web", Image: "nginx", Ports: []compose.PortMapping{
			{Raw: "80:80", HostPort: 80, TargetPort: 80},
		}},
	}
	r := Analyze(collected(svcs, nil))
	if r.Summary.TotalServices != 3 {
		t.Fatalf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected some findings for sensitive services")
	}
}
