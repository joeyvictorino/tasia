package linklocal

import (
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

func svc(name string) compose.Service {
	return compose.Service{Name: name}
}

func TestIsLinkLocal(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"169.254.1.1", true},
		{"169.254.0.0", true},
		{"fe80::1", true},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"127.0.0.1", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isLinkLocal(tt.ip)
		if got != tt.want {
			t.Errorf("isLinkLocal(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsWildcard(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"0.0.0.0", true},
		{"::", true},
		{"", true},
		{"127.0.0.1", false},
		{"192.168.1.1", false},
	}
	for _, tt := range tests {
		got := isWildcard(tt.ip)
		if got != tt.want {
			t.Errorf("isWildcard(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"localhost", true},
		{"0.0.0.0", false},
		{"192.168.1.1", false},
	}
	for _, tt := range tests {
		got := isLoopback(tt.ip)
		if got != tt.want {
			t.Errorf("isLoopback(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsMulticastDNSPort(t *testing.T) {
	tests := []struct {
		port int
		want bool
	}{
		{5353, true},
		{53, false},
		{80, false},
		{0, false},
	}
	for _, tt := range tests {
		got := isMulticastDNSPort(tt.port)
		if got != tt.want {
			t.Errorf("isMulticastDNSPort(%d) = %v, want %v", tt.port, got, tt.want)
		}
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestLinkLocalBind(t *testing.T) {
	s := svc("api")
	s.Ports = []compose.PortMapping{
		{HostIP: "169.254.1.1", HostPort: 8080, TargetPort: 8080},
	}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "link_local_bind" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected link_local_bind finding")
	}
}

func TestWildcardBind(t *testing.T) {
	s := svc("web")
	s.Ports = []compose.PortMapping{
		{HostIP: "0.0.0.0", HostPort: 80, TargetPort: 80},
	}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "wildcard_bind" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected wildcard_bind finding")
	}
}

func TestDefaultBindIsWildcard(t *testing.T) {
	s := svc("web")
	s.Ports = []compose.PortMapping{
		{HostIP: "", HostPort: 80, TargetPort: 80},
	}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "wildcard_bind" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected wildcard_bind for empty HostIP")
	}
}

func TestLoopbackOnly(t *testing.T) {
	s := svc("internal")
	s.Ports = []compose.PortMapping{
		{HostIP: "127.0.0.1", HostPort: 3000, TargetPort: 3000},
	}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "loopback_only" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected loopback_only finding")
	}
}

func TestMulticastDNSPort(t *testing.T) {
	s := svc("mdns")
	s.Ports = []compose.PortMapping{
		{HostIP: "0.0.0.0", HostPort: 5353, TargetPort: 5353},
	}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "multicast_dns_port" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected multicast_dns_port finding")
	}
}

func TestLinkLocalDNS(t *testing.T) {
	s := svc("app")
	s.DNS = []string{"169.254.169.254"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "link_local_dns" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected link_local_dns finding")
	}
}

func TestCleanService(t *testing.T) {
	s := svc("clean")
	s.Ports = []compose.PortMapping{
		{HostIP: "127.0.0.1", HostPort: 8080, TargetPort: 8080},
	}
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "link_local_bind" || f.Rule == "wildcard_bind" || f.Rule == "multicast_dns_port" {
				t.Fatalf("unexpected finding %s for clean service", f.Rule)
			}
		}
	}
}

func TestNoPortsNoProblem(t *testing.T) {
	s := svc("worker")
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "wildcard_bind" || f.Rule == "link_local_bind" {
				t.Fatalf("unexpected binding finding for service with no ports: %s", f.Rule)
			}
		}
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("web")
	s1.Ports = []compose.PortMapping{{HostIP: "0.0.0.0", HostPort: 80, TargetPort: 80}}
	s2 := svc("internal")
	s2.Ports = []compose.PortMapping{{HostIP: "127.0.0.1", HostPort: 3000, TargetPort: 3000}}
	c := collected(s1, s2)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text")
	}
	if !containsStr(text, "0 findings") {
		t.Fatal("expected '0 findings'")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	s := svc("api")
	s.Ports = []compose.PortMapping{{HostIP: "169.254.1.1", HostPort: 80, TargetPort: 80}}
	c := collected(s)
	r := Analyze(c)
	text := FormatText(r)
	if !containsStr(text, "api") {
		t.Fatal("expected service name")
	}
	if !containsStr(text, "Link-Local") {
		t.Fatal("expected header")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
