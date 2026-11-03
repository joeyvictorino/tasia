package memcachedaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestMemcachedMissingAuth(t *testing.T) {
	svc := compose.Service{
		Name:  "memcached",
		Image: "memcached:1.6",
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_auth" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected missing_auth finding")
	}
}

func TestMemcachedWithSASL(t *testing.T) {
	svc := compose.Service{
		Name:        "memcached",
		Image:       "memcached:1.6",
		Environment: []string{"MEMCACHED_SASL_PWDB=/etc/memcached/sasldb2"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_auth" {
				t.Error("should not flag missing_auth when SASL is configured")
			}
		}
	}
}

func TestMemcachedPlaintextConnection(t *testing.T) {
	svc := compose.Service{
		Name:        "memcached",
		Image:       "memcached:1.6",
		Environment: []string{"MEMCACHED_SASL_PWDB=/etc/sasldb2"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "plaintext_connection" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected plaintext_connection finding")
	}
}

func TestMemcachedWithTLS(t *testing.T) {
	svc := compose.Service{
		Name:  "memcached",
		Image: "memcached:1.6",
		Environment: []string{
			"MEMCACHED_SASL_PWDB=/etc/sasldb2",
			"MEMCACHED_TLS_CERT=/certs/cert.pem",
			"MEMCACHED_TLS_KEY=/certs/key.pem",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "plaintext_connection" {
				t.Error("should not flag plaintext when TLS is configured")
			}
		}
	}
}

func TestMemcachedExposedPort(t *testing.T) {
	svc := compose.Service{
		Name:  "memcached",
		Image: "memcached:1.6",
		Ports: []compose.PortMapping{
			{HostPort: 11211, TargetPort: 11211, Raw: "11211:11211"},
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_port" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected exposed_port finding")
	}
}

func TestMemcachedLocalhostPort(t *testing.T) {
	svc := compose.Service{
		Name:  "memcached",
		Image: "memcached:1.6",
		Ports: []compose.PortMapping{
			{HostPort: 11211, TargetPort: 11211, Raw: "127.0.0.1:11211:11211", HostIP: "127.0.0.1"},
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_port" {
				t.Error("should not flag port bound to localhost")
			}
		}
	}
}

func TestMemcachedDefaultCredentials(t *testing.T) {
	svc := compose.Service{
		Name:  "memcached",
		Image: "memcached:1.6",
		Environment: []string{
			"MEMCACHED_SASL_PWDB=/etc/sasldb2",
			"MEMCACHED_CREDENTIALS=admin:admin",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "default_credentials" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected default_credentials finding")
	}
}

func TestMemcachedUDPEnabled(t *testing.T) {
	svc := compose.Service{
		Name:        "memcached",
		Image:       "memcached:1.6",
		Environment: []string{"MEMCACHED_UDP_PORT=11211"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "udp_enabled" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected udp_enabled finding")
	}
}

func TestMemcachedLargeMemory(t *testing.T) {
	svc := compose.Service{
		Name:  "memcached",
		Image: "memcached:1.6",
		Environment: []string{
			"MEMCACHED_SASL_PWDB=/etc/sasldb2",
			"MEMCACHED_TLS_CERT=/certs/cert.pem",
			"MEMCACHED_MAX_MEMORY=10240m",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "large_memory_limit" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected large_memory_limit finding")
	}
}

func TestNonMemcachedService(t *testing.T) {
	svc := compose.Service{
		Name:  "nginx",
		Image: "nginx:latest",
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		if len(sr.Findings) > 0 {
			t.Error("non-memcached service should have no findings")
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	svc := compose.Service{
		Name:  "memcached",
		Image: "memcached:1.6",
		Ports: []compose.PortMapping{
			{HostPort: 11211, TargetPort: 11211, Raw: "11211:11211"},
		},
	}
	r := Analyze(makeCollected(svc))
	if r.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.MissingAuth != 1 {
		t.Errorf("expected 1 missing auth, got %d", r.Summary.MissingAuth)
	}
	if r.Summary.PlaintextConn != 1 {
		t.Errorf("expected 1 plaintext, got %d", r.Summary.PlaintextConn)
	}
	if r.Summary.ExposedPorts != 1 {
		t.Errorf("expected 1 exposed port, got %d", r.Summary.ExposedPorts)
	}
}

func TestFormatTextOutput(t *testing.T) {
	svc := compose.Service{
		Name:  "memcached",
		Image: "memcached:1.6",
	}
	r := Analyze(makeCollected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "Memcached Security Audit") {
		t.Error("expected header in output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/empty"})
	text := FormatText(r)
	if !strings.Contains(text, "0 findings") {
		t.Error("expected zero findings in empty report")
	}
}

func TestMultipleMemcachedServices(t *testing.T) {
	svc1 := compose.Service{
		Name:  "cache1",
		Image: "memcached:1.6",
	}
	svc2 := compose.Service{
		Name:  "cache2",
		Image: "bitnami/memcached:latest",
		Environment: []string{
			"MEMCACHED_SASL_PWDB=/etc/sasldb2",
			"MEMCACHED_TLS_CERT=/certs/cert.pem",
		},
	}
	r := Analyze(makeCollected(svc1, svc2))
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.MissingAuth != 1 {
		t.Errorf("expected 1 missing auth (only svc1), got %d", r.Summary.MissingAuth)
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/my/project"}
	r := Analyze(c)
	if r.Path != "/my/project" {
		t.Errorf("expected path /my/project, got %s", r.Path)
	}
}

func TestIsMemcachedImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"memcached:1.6", true},
		{"bitnami/memcached:latest", true},
		{"library/memcached:alpine", true},
		{"nginx:latest", false},
		{"redis:7", false},
	}
	for _, tt := range tests {
		if got := isMemcachedImage(tt.image); got != tt.want {
			t.Errorf("isMemcachedImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestMemcachedWithUsername(t *testing.T) {
	svc := compose.Service{
		Name:        "memcached",
		Image:       "memcached:1.6",
		Environment: []string{"MEMCACHED_USERNAME=admin"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_auth" {
				t.Error("should not flag missing_auth when username is set")
			}
		}
	}
}
