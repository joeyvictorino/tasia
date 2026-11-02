package ratelimit

import (
	"fmt"
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

func mkPorts(specs ...string) []compose.PortMapping {
	var ports []compose.PortMapping
	for _, s := range specs {
		pm := compose.PortMapping{Raw: s}
		parts := strings.Split(s, ":")
		if len(parts) >= 2 {
			// simple parse for tests
			var host, target int
			fmt.Sscanf(parts[0], "%d", &host)
			fmt.Sscanf(parts[1], "%d", &target)
			pm.HostPort = host
			pm.TargetPort = target
		}
		ports = append(ports, pm)
	}
	return ports
}

func TestNoServices(t *testing.T) {
	r := Analyze(mkCollected())
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestExposedWithoutRateLimit(t *testing.T) {
	svc := compose.Service{
		Name:  "api-server",
		Image: "nginx:latest",
		Ports: mkPorts("8080:80"),
	}
	r := Analyze(mkCollected(svc))
	if r.Summary.ExposedServices != 1 {
		t.Errorf("expected 1 exposed, got %d", r.Summary.ExposedServices)
	}
	if r.Summary.WithoutRateLimit != 1 {
		t.Errorf("expected 1 without rate limit, got %d", r.Summary.WithoutRateLimit)
	}
	if r.Summary.TotalFindings == 0 {
		t.Error("expected findings for exposed API without rate limit")
	}
}

func TestExposedWithRateLimit(t *testing.T) {
	svc := compose.Service{
		Name:   "api-gateway",
		Image:  "nginx:latest",
		Ports:  mkPorts("80:80"),
		Labels: map[string]string{"traefik.http.middlewares.rl": "rateLimit.average=100"},
	}
	r := Analyze(mkCollected(svc))
	if r.Summary.WithRateLimit != 1 {
		t.Errorf("expected 1 with rate limit, got %d", r.Summary.WithRateLimit)
	}
}

func TestUnexposedService(t *testing.T) {
	svc := compose.Service{
		Name:  "database",
		Image: "postgres:15",
	}
	r := Analyze(mkCollected(svc))
	if r.Summary.ExposedServices != 0 {
		t.Errorf("expected 0 exposed, got %d", r.Summary.ExposedServices)
	}
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for unexposed service, got %d", r.Summary.TotalFindings)
	}
}

func TestRateLimitInEnv(t *testing.T) {
	svc := compose.Service{
		Name:        "web",
		Image:       "node:18",
		Ports:       mkPorts("3000:3000"),
		Environment: []string{"RATE_LIMIT_MAX=100"},
	}
	r := Analyze(mkCollected(svc))
	if r.Summary.WithRateLimit != 1 {
		t.Errorf("expected rate limit detected from env, got %d with limit", r.Summary.WithRateLimit)
	}
}

func TestRateLimitInCommand(t *testing.T) {
	svc := compose.Service{
		Name:    "proxy",
		Image:   "envoy:latest",
		Ports:   mkPorts("8080:8080"),
		Command: []string{"--rate-limit-service=rls"},
	}
	r := Analyze(mkCollected(svc))
	if r.Summary.WithRateLimit != 1 {
		t.Errorf("expected rate limit detected from command, got %d with limit", r.Summary.WithRateLimit)
	}
}

func TestSensitivePortFinding(t *testing.T) {
	svc := compose.Service{
		Name:  "api",
		Image: "fastapi:latest",
		Ports: mkPorts("443:443"),
	}
	r := Analyze(mkCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "rate_limit_missing_sensitive_port" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected sensitive port finding for 443")
	}
}

func TestIsAPIService(t *testing.T) {
	tests := []struct {
		name  string
		image string
		want  bool
	}{
		{"api-server", "custom:latest", true},
		{"backend", "myapp:1.0", true},
		{"worker", "custom:latest", false},
		{"db", "postgres:15", false},
		{"proxy", "nginx:latest", true},
	}
	for _, tt := range tests {
		svc := compose.Service{Name: tt.name, Image: tt.image}
		got := isAPIService(svc)
		if got != tt.want {
			t.Errorf("isAPIService(%q, %q) = %v, want %v", tt.name, tt.image, got, tt.want)
		}
	}
}

func TestFormatText(t *testing.T) {
	svc := compose.Service{
		Name:  "api",
		Image: "nginx:latest",
		Ports: mkPorts("80:80"),
	}
	r := Analyze(mkCollected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "Rate Limit") {
		t.Error("missing header")
	}
}

func TestMultipleServices(t *testing.T) {
	svcs := []compose.Service{
		{Name: "api", Image: "nginx:latest", Ports: mkPorts("80:80")},
		{Name: "db", Image: "postgres:15"},
		{Name: "cache", Image: "redis:7", Ports: mkPorts("6379:6379")},
	}
	r := Analyze(mkCollected(svcs...))
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.ExposedServices != 2 {
		t.Errorf("expected 2 exposed, got %d", r.Summary.ExposedServices)
	}
}
