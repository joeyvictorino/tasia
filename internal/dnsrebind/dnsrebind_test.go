package dnsrebind

import (
	"encoding/json"
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

func hasRule(sr ServiceResult, rule string) bool {
	for _, f := range sr.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestHostNetNoDNS(t *testing.T) {
	c := collected(compose.Service{
		Name:        "agent",
		NetworkMode: "host",
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "dnsrebind_host_net_no_dns") {
		t.Error("expected dnsrebind_host_net_no_dns for host network without DNS")
	}
	if r.Summary.HostNetNoDNS != 1 {
		t.Errorf("expected 1 host net no dns, got %d", r.Summary.HostNetNoDNS)
	}
}

func TestHostNetWithDNSNotFlagged(t *testing.T) {
	c := collected(compose.Service{
		Name:        "agent",
		NetworkMode: "host",
		DNS:         []string{"10.0.0.1"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "dnsrebind_host_net_no_dns") {
		t.Error("should not flag host net with explicit DNS")
	}
}

func TestPublicDNSInternalService(t *testing.T) {
	c := collected(compose.Service{
		Name: "internal-db",
		DNS:  []string{"8.8.8.8"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "dnsrebind_public_dns_internal") {
		t.Error("expected dnsrebind_public_dns_internal for internal service with public DNS")
	}
	if r.Summary.PublicDNSInPrivate != 1 {
		t.Errorf("expected 1 public dns in private, got %d", r.Summary.PublicDNSInPrivate)
	}
}

func TestPublicDNSExternalServiceSafe(t *testing.T) {
	c := collected(compose.Service{
		Name: "frontend",
		DNS:  []string{"8.8.8.8"},
		Ports: []compose.PortMapping{
			{HostPort: 80, TargetPort: 80},
		},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "dnsrebind_public_dns_internal") {
		t.Error("should not flag external service with public DNS")
	}
}

func TestWildcardDNSSearch(t *testing.T) {
	c := collected(compose.Service{
		Name:      "app",
		DNSSearch: []string{"."},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "dnsrebind_wildcard_search") {
		t.Error("expected dnsrebind_wildcard_search for '.' search domain")
	}
	if r.Summary.WildcardDNSSearch != 1 {
		t.Errorf("expected 1 wildcard, got %d", r.Summary.WildcardDNSSearch)
	}
}

func TestEmptyDNSSearch(t *testing.T) {
	c := collected(compose.Service{
		Name:      "app",
		DNSSearch: []string{""},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "dnsrebind_wildcard_search") {
		t.Error("expected dnsrebind_wildcard_search for empty search domain")
	}
}

func TestSpecificDNSSearchSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:      "app",
		DNSSearch: []string{"internal.corp.io"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "dnsrebind_wildcard_search") {
		t.Error("should not flag specific DNS search domain")
	}
}

func TestHostNetAllPublicDNS(t *testing.T) {
	c := collected(compose.Service{
		Name:        "monitor",
		NetworkMode: "host",
		DNS:         []string{"8.8.8.8", "1.1.1.1"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "dnsrebind_host_all_public_dns") {
		t.Error("expected dnsrebind_host_all_public_dns for host net with only public DNS")
	}
}

func TestHostNetMixedDNSSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:        "monitor",
		NetworkMode: "host",
		DNS:         []string{"10.0.0.1", "8.8.8.8"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "dnsrebind_host_all_public_dns") {
		t.Error("should not flag mixed DNS (has private resolver)")
	}
}

func TestWebPortNoDNSRestrict(t *testing.T) {
	c := collected(compose.Service{
		Name: "webapp",
		Ports: []compose.PortMapping{
			{HostPort: 8080, TargetPort: 8080},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "dnsrebind_web_no_dns_restrict") {
		t.Error("expected dnsrebind_web_no_dns_restrict for web service without DNS config")
	}
	if r.Summary.NoDNSRestriction != 1 {
		t.Errorf("expected 1 no dns restriction, got %d", r.Summary.NoDNSRestriction)
	}
}

func TestNonWebPortSafe(t *testing.T) {
	c := collected(compose.Service{
		Name: "redis",
		Ports: []compose.PortMapping{
			{HostPort: 6379, TargetPort: 6379},
		},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "dnsrebind_web_no_dns_restrict") {
		t.Error("should not flag non-web port")
	}
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{
		Name:  "clean",
		Image: "nginx:latest",
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Services[0].Findings))
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{
		Name:        "agent",
		NetworkMode: "host",
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{
		Name:        "svc",
		NetworkMode: "host",
	})
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var r2 Report
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if r2.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service after round-trip, got %d", r2.Summary.TotalServices)
	}
}
