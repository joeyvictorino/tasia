package dns

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: svcs},
		},
	}
}

func TestAnalyze_NoDNS(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Summary.TotalServices != 1 {
		t.Fatalf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithDNS != 0 {
		t.Fatalf("expected 0 with DNS, got %d", r.Summary.WithDNS)
	}
	if r.Services[0].Grade != "A" {
		t.Fatalf("expected grade A, got %s", r.Services[0].Grade)
	}
}

func TestAnalyze_PublicResolver(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		DNS:  []string{"8.8.8.8"},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) == 0 {
		t.Fatal("expected findings for public resolver")
	}
	f := r.Services[0].Findings[0]
	if f.Category != "public_resolver" {
		t.Fatalf("expected public_resolver, got %s", f.Category)
	}
	if f.Severity != "medium" {
		t.Fatalf("expected medium severity, got %s", f.Severity)
	}
	if !strings.Contains(f.Detail, "Google") {
		t.Fatalf("expected Google in detail, got %s", f.Detail)
	}
}

func TestAnalyze_ExternalDNS(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		DNS:  []string{"203.0.113.53"},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) < 1 {
		t.Fatal("expected external DNS finding")
	}
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "external_dns" {
			found = true
			if f.Severity != "high" {
				t.Fatalf("expected high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected external_dns finding")
	}
}

func TestAnalyze_LoopbackNotFlagged(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		DNS:  []string{"127.0.0.1"},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Category == "external_dns" || f.Category == "public_resolver" {
			t.Fatalf("loopback should not be flagged, got %s", f.Category)
		}
	}
}

func TestAnalyze_PrivateIPNotFlagged(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		DNS:  []string{"10.0.0.53"},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Category == "external_dns" || f.Category == "public_resolver" {
			t.Fatalf("private IP should not be flagged as external, got %s", f.Category)
		}
	}
}

func TestAnalyze_MissingDNSSearch(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		DNS:  []string{"10.0.0.53"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "missing_dns_search" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected missing_dns_search finding")
	}
}

func TestAnalyze_BroadDNSSearch(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:      "app",
		DNS:       []string{"10.0.0.53"},
		DNSSearch: []string{"example.com"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Category == "broad_dns_search" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected broad_dns_search finding for .com domain")
	}
}

func TestAnalyze_InternalDNSSearchNotFlagged(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:      "app",
		DNS:       []string{"10.0.0.53"},
		DNSSearch: []string{"internal.local"},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Category == "broad_dns_search" {
			t.Fatal("internal.local should not be flagged as broad")
		}
	}
}

func TestAnalyze_ScoreFloor(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		DNS:  []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"},
	})
	r := Analyze(c)
	if r.Services[0].Score < 0 {
		t.Fatalf("score should not go below 0, got %d", r.Services[0].Score)
	}
	if r.Services[0].Grade != "F" {
		t.Fatalf("expected grade F, got %s", r.Services[0].Grade)
	}
}

func TestScoreToGrade(t *testing.T) {
	tests := []struct {
		score int
		grade string
	}{
		{100, "A"}, {90, "A"}, {89, "B"}, {80, "B"},
		{79, "C"}, {70, "C"}, {69, "D"}, {60, "D"},
		{59, "F"}, {0, "F"},
	}
	for _, tt := range tests {
		if g := scoreToGrade(tt.score); g != tt.grade {
			t.Errorf("scoreToGrade(%d) = %s, want %s", tt.score, g, tt.grade)
		}
	}
}

func TestFormatText(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "app",
		DNS:  []string{"8.8.8.8"},
	})
	r := Analyze(c)
	out := FormatText(r)
	if !strings.Contains(out, "DNS Configuration Audit") {
		t.Fatal("expected header in text output")
	}
	if !strings.Contains(out, "app") {
		t.Fatal("expected service name in text output")
	}
	if !strings.Contains(out, "public_resolver") {
		t.Fatal("expected finding category in text output")
	}
}

func TestAnalyze_MultipleServices(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "clean"},
		compose.Service{Name: "dirty", DNS: []string{"8.8.8.8"}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithDNS != 1 {
		t.Fatalf("expected 1 with DNS, got %d", r.Summary.WithDNS)
	}
	if r.Summary.WithIssues != 1 {
		t.Fatalf("expected 1 with issues, got %d", r.Summary.WithIssues)
	}
}

func TestAnalyze_AllPublicResolvers(t *testing.T) {
	for ip, provider := range publicResolvers {
		c := mkCollected(compose.Service{
			Name: "svc",
			DNS:  []string{ip},
		})
		r := Analyze(c)
		found := false
		for _, f := range r.Services[0].Findings {
			if f.Category == "public_resolver" && strings.Contains(f.Detail, provider) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected public_resolver for %s (%s)", ip, provider)
		}
	}
}

func TestAnalyze_DNSSearchSingleLabel(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:      "app",
		DNS:       []string{"10.0.0.53"},
		DNSSearch: []string{"local"},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Category == "broad_dns_search" {
			t.Fatal("single-label domain should be skipped")
		}
	}
}

func TestAnalyze_DNSSearchTrailingDot(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:      "app",
		DNS:       []string{"10.0.0.53"},
		DNSSearch: []string{"example.com."},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Category == "broad_dns_search" {
			t.Fatal("FQDN with trailing dot should be skipped")
		}
	}
}
