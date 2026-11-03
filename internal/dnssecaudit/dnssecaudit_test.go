package dnssecaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func svc(name string, opts ...func(*compose.Service)) compose.Service {
	s := compose.Service{Name: name}
	for _, o := range opts {
		o(&s)
	}
	return s
}

func withImage(img string) func(*compose.Service) {
	return func(s *compose.Service) { s.Image = img }
}

func withEnv(envs ...string) func(*compose.Service) {
	return func(s *compose.Service) { s.Environment = append(s.Environment, envs...) }
}

func withPorts(ports ...string) func(*compose.Service) {
	return func(s *compose.Service) {
		for _, p := range ports {
			s.Ports = append(s.Ports, compose.PortMapping{Raw: p})
		}
	}
}

func withPortsFull(ports ...compose.PortMapping) func(*compose.Service) {
	return func(s *compose.Service) { s.Ports = append(s.Ports, ports...) }
}

func withVolumes(vols ...string) func(*compose.Service) {
	return func(s *compose.Service) { s.Volumes = append(s.Volumes, vols...) }
}

func findRule(results []ServiceResult, ruleID string) *Finding {
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Rule == ruleID {
				return &f
			}
		}
	}
	return nil
}

func TestMissingDNSSEC(t *testing.T) {
	c := mkCollected(svc("dns", withImage("coredns/coredns")))
	r := Analyze(c)
	if findRule(r.Results, "DNS-001") == nil {
		t.Fatal("expected DNS-001 for missing DNSSEC")
	}
}

func TestDNSSECConfigured(t *testing.T) {
	c := mkCollected(svc("dns", withImage("coredns/coredns"), withEnv("DNSSEC_ENABLE=true")))
	r := Analyze(c)
	if findRule(r.Results, "DNS-001") != nil {
		t.Fatal("unexpected DNS-001 when DNSSEC enabled")
	}
}

func TestDNSSECVolumeMount(t *testing.T) {
	c := mkCollected(svc("dns", withImage("bind9"), withVolumes("./zones/dnssec-keys:/etc/bind/dnssec")))
	r := Analyze(c)
	if findRule(r.Results, "DNS-001") != nil {
		t.Fatal("unexpected DNS-001 when DNSSEC volume mounted")
	}
}

func TestOpenZoneTransfer(t *testing.T) {
	c := mkCollected(svc("dns", withImage("bind9"), withEnv("ALLOW_TRANSFER=any")))
	r := Analyze(c)
	if findRule(r.Results, "DNS-002") == nil {
		t.Fatal("expected DNS-002 for open zone transfer")
	}
}

func TestRestrictedZoneTransfer(t *testing.T) {
	c := mkCollected(svc("dns", withImage("bind9"), withEnv("ALLOW_TRANSFER=10.0.0.5")))
	r := Analyze(c)
	if findRule(r.Results, "DNS-002") != nil {
		t.Fatal("unexpected DNS-002 when transfer restricted")
	}
}

func TestRecursionEnabled(t *testing.T) {
	c := mkCollected(svc("dns", withImage("bind9"), withEnv("RECURSION=yes")))
	r := Analyze(c)
	if findRule(r.Results, "DNS-003") == nil {
		t.Fatal("expected DNS-003 for recursion enabled")
	}
}

func TestRecursionDisabled(t *testing.T) {
	c := mkCollected(svc("dns", withImage("bind9"), withEnv("RECURSION=no")))
	r := Analyze(c)
	if findRule(r.Results, "DNS-003") != nil {
		t.Fatal("unexpected DNS-003 when recursion disabled")
	}
}

func TestMissingTSIG(t *testing.T) {
	c := mkCollected(svc("dns", withImage("powerdns")))
	r := Analyze(c)
	if findRule(r.Results, "DNS-004") == nil {
		t.Fatal("expected DNS-004 for missing TSIG")
	}
}

func TestTSIGConfigured(t *testing.T) {
	c := mkCollected(svc("dns", withImage("powerdns"), withEnv("TSIG_KEY=hmac-sha256:mykey")))
	r := Analyze(c)
	if findRule(r.Results, "DNS-004") != nil {
		t.Fatal("unexpected DNS-004 when TSIG configured")
	}
}

func TestTSIGVolumeMount(t *testing.T) {
	c := mkCollected(svc("dns", withImage("bind9"), withVolumes("./config/rndc.key:/etc/bind/rndc.key")))
	r := Analyze(c)
	if findRule(r.Results, "DNS-004") != nil {
		t.Fatal("unexpected DNS-004 when TSIG key mounted")
	}
}

func TestCachePoisoningRisk(t *testing.T) {
	c := mkCollected(svc("dns", withImage("unbound")))
	r := Analyze(c)
	if findRule(r.Results, "DNS-005") == nil {
		t.Fatal("expected DNS-005 for cache poisoning risk")
	}
}

func TestSourcePortRandomized(t *testing.T) {
	c := mkCollected(svc("dns", withImage("unbound"), withEnv("SOURCE_PORT_RANDOMIZE=true")))
	r := Analyze(c)
	if findRule(r.Results, "DNS-005") != nil {
		t.Fatal("unexpected DNS-005 when source port randomized")
	}
}

func TestExposedWithoutRateLimit(t *testing.T) {
	c := mkCollected(svc("dns", withImage("coredns/coredns"),
		withPortsFull(compose.PortMapping{HostPort: 53, TargetPort: 53, Raw: "53:53"})))
	r := Analyze(c)
	if findRule(r.Results, "DNS-006") == nil {
		t.Fatal("expected DNS-006 for exposed port without rate limit")
	}
}

func TestExposedWithRateLimit(t *testing.T) {
	c := mkCollected(svc("dns", withImage("coredns/coredns"),
		withPortsFull(compose.PortMapping{HostPort: 53, TargetPort: 53, Raw: "53:53"}),
		withEnv("RATE_LIMIT=100")))
	r := Analyze(c)
	if findRule(r.Results, "DNS-006") != nil {
		t.Fatal("unexpected DNS-006 when rate limit configured")
	}
}

func TestLocalhostPortNotExposed(t *testing.T) {
	c := mkCollected(svc("dns", withImage("coredns/coredns"),
		withPortsFull(compose.PortMapping{HostPort: 53, TargetPort: 53, Raw: "127.0.0.1:53:53", HostIP: "127.0.0.1"})))
	r := Analyze(c)
	if findRule(r.Results, "DNS-006") != nil {
		t.Fatal("unexpected DNS-006 for localhost binding")
	}
}

func TestNonDNSServiceIgnored(t *testing.T) {
	c := mkCollected(svc("web", withImage("nginx:latest")))
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestIsDNSImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"coredns/coredns:1.11", true},
		{"ubuntu/bind9:latest", true},
		{"powerdns/pdns-auth:4.8", true},
		{"nlnetlabs/unbound:latest", true},
		{"pihole/pihole:latest", true},
		{"nginx:latest", false},
		{"postgres:15", false},
	}
	for _, tt := range tests {
		if got := isDNSImage(tt.image); got != tt.want {
			t.Errorf("isDNSImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	c := mkCollected(svc("dns", withImage("bind9"),
		withEnv("ALLOW_TRANSFER=any", "RECURSION=yes"),
		withPortsFull(compose.PortMapping{HostPort: 53, TargetPort: 53, Raw: "53:53"})))
	r := Analyze(c)
	if r.Summary.OpenZoneTransfer != 1 {
		t.Errorf("expected 1 open zone transfer, got %d", r.Summary.OpenZoneTransfer)
	}
	if r.Summary.RecursionEnabled != 1 {
		t.Errorf("expected 1 recursion enabled, got %d", r.Summary.RecursionEnabled)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(svc("dns", withImage("coredns/coredns")))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "DNS Server Security Audit") {
		t.Fatal("expected header in output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/empty"})
	text := FormatText(r)
	if !strings.Contains(text, "0") {
		t.Fatal("expected zero counts in empty report")
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/my/project"}
	r := Analyze(c)
	if r.Path != "/my/project" {
		t.Errorf("expected path /my/project, got %s", r.Path)
	}
}
