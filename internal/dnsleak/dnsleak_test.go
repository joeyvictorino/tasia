package dnsleak

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	cf := compose.File{Path: "docker-compose.yml", Services: services}
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{cf}}
}

func findRule(results []ServiceResult, rule string) bool {
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return true
			}
		}
	}
	return false
}

func TestNoDNSConfig(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if !findRule(r.Services, "dnsleak_no_dns_config") {
		t.Error("expected no_dns_config finding")
	}
}

func TestWithPrivateDNS(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", DNS: []string{"10.0.0.53"}})
	r := Analyze(c)
	if findRule(r.Services, "dnsleak_no_dns_config") {
		t.Error("should not flag service with DNS config")
	}
	if findRule(r.Services, "dnsleak_public_dns") {
		t.Error("should not flag private DNS")
	}
}

func TestPublicDNSGoogle(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", DNS: []string{"8.8.8.8"}})
	r := Analyze(c)
	if !findRule(r.Services, "dnsleak_public_dns") {
		t.Error("expected public_dns finding for 8.8.8.8")
	}
}

func TestPublicDNSCloudflare(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", DNS: []string{"1.1.1.1"}})
	r := Analyze(c)
	if !findRule(r.Services, "dnsleak_public_dns") {
		t.Error("expected public_dns finding for 1.1.1.1")
	}
}

func TestPublicDNSQuad9(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", DNS: []string{"9.9.9.9"}})
	r := Analyze(c)
	if !findRule(r.Services, "dnsleak_public_dns") {
		t.Error("expected public_dns finding for 9.9.9.9")
	}
}

func TestHostNetworkNoCustomDNS(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", NetworkMode: "host"})
	r := Analyze(c)
	if !findRule(r.Services, "dnsleak_host_network") {
		t.Error("expected host_network finding")
	}
}

func TestHostNetworkWithDNS(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", NetworkMode: "host", DNS: []string{"10.0.0.53"}})
	r := Analyze(c)
	if findRule(r.Services, "dnsleak_host_network") {
		t.Error("should not flag host network with custom DNS")
	}
}

func TestWildcardSearch(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", DNSSearch: []string{"."}})
	r := Analyze(c)
	if !findRule(r.Services, "dnsleak_wildcard_search") {
		t.Error("expected wildcard_search finding")
	}
}

func TestNormalSearch(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", DNSSearch: []string{"internal.corp"}})
	r := Analyze(c)
	if findRule(r.Services, "dnsleak_wildcard_search") {
		t.Error("should not flag normal search domain")
	}
}

func TestMismatchedDNS(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "web", DNS: []string{"10.0.0.53"}},
		compose.Service{Name: "api", DNS: []string{"10.0.0.54"}},
	)
	r := Analyze(c)
	if !findRule(r.Services, "dnsleak_mismatched_dns") {
		t.Error("expected mismatched_dns finding")
	}
}

func TestMatchingDNS(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "web", DNS: []string{"10.0.0.53"}},
		compose.Service{Name: "api", DNS: []string{"10.0.0.53"}},
	)
	r := Analyze(c)
	if findRule(r.Services, "dnsleak_mismatched_dns") {
		t.Error("should not flag matching DNS configs")
	}
}

func TestMultiplePublicDNS(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", DNS: []string{"8.8.8.8", "1.1.1.1"}})
	r := Analyze(c)
	if r.Summary.PublicDNS < 2 {
		t.Errorf("expected at least 2 public DNS findings, got %d", r.Summary.PublicDNS)
	}
}

func TestSummaryTotals(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "a", DNS: []string{"8.8.8.8"}},
		compose.Service{Name: "b"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 total findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", DNS: []string{"8.8.8.8"}})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "DNS Leak") {
		t.Error("expected 'DNS Leak' in output")
	}
	if !strings.Contains(text, "web") {
		t.Error("expected service name in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", DNS: []string{"10.0.0.53"}})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "no findings") {
		t.Error("expected 'no findings' in output")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestReportPath(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Path != "/test" {
		t.Errorf("expected path /test, got %s", r.Path)
	}
}

func TestOpenDNSDetected(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", DNS: []string{"208.67.222.222"}})
	r := Analyze(c)
	if !findRule(r.Services, "dnsleak_public_dns") {
		t.Error("expected public_dns finding for OpenDNS")
	}
}
