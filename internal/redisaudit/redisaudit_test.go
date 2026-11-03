package redisaudit

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

func TestRedisNoAuth(t *testing.T) {
	svc := compose.Service{
		Name:        "redis",
		Image:       "redis:7",
		Environment: []string{},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_auth" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected no_auth finding")
	}
}

func TestRedisWithAuth(t *testing.T) {
	svc := compose.Service{
		Name:        "redis",
		Image:       "redis:7",
		Environment: []string{"REDIS_PASSWORD=mysecretpass123"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_auth" {
				t.Error("should not flag no_auth when password is set")
			}
		}
	}
}

func TestRedisExposedPort(t *testing.T) {
	svc := compose.Service{
		Name:  "redis",
		Image: "redis:7",
		Ports: []compose.PortMapping{
			{HostPort: 6379, TargetPort: 6379, Raw: "6379:6379"},
		},
		Environment: []string{"REDIS_PASSWORD=secure123xyz"},
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

func TestRedisLocalhostPort(t *testing.T) {
	svc := compose.Service{
		Name:  "redis",
		Image: "redis:7",
		Ports: []compose.PortMapping{
			{HostPort: 6379, TargetPort: 6379, Raw: "127.0.0.1:6379:6379", HostIP: "127.0.0.1"},
		},
		Environment: []string{"REDIS_PASSWORD=secure123xyz"},
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

func TestRedisMissingTLS(t *testing.T) {
	svc := compose.Service{
		Name:        "redis",
		Image:       "redis:7",
		Environment: []string{"REDIS_PASSWORD=secure123xyz"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_tls" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected missing_tls finding")
	}
}

func TestRedisWithTLS(t *testing.T) {
	svc := compose.Service{
		Name:  "redis",
		Image: "redis:7",
		Environment: []string{
			"REDIS_PASSWORD=secure123xyz",
			"REDIS_TLS_ENABLED=yes",
			"REDIS_TLS_CERT_FILE=/certs/redis.crt",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_tls" {
				t.Error("should not flag missing_tls when TLS configured")
			}
		}
	}
}

func TestRedisDefaultPassword(t *testing.T) {
	svc := compose.Service{
		Name:        "redis",
		Image:       "redis:7",
		Environment: []string{"REDIS_PASSWORD=password"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "default_password" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected default_password finding")
	}
}

func TestRedisNoMaxMemPolicy(t *testing.T) {
	svc := compose.Service{
		Name:        "redis",
		Image:       "redis:7",
		Environment: []string{"REDIS_PASSWORD=secure123xyz"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_maxmem_policy" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected no_maxmem_policy finding")
	}
}

func TestNonRedisService(t *testing.T) {
	svc := compose.Service{
		Name:  "nginx",
		Image: "nginx:latest",
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		if len(sr.Findings) > 0 {
			t.Error("non-redis service should have no findings")
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	svc := compose.Service{
		Name:  "redis",
		Image: "redis:7",
		Ports: []compose.PortMapping{
			{HostPort: 6379, TargetPort: 6379, Raw: "6379:6379"},
		},
		Environment: []string{},
	}
	r := Analyze(makeCollected(svc))
	if r.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.NoAuth != 1 {
		t.Errorf("expected 1 no_auth, got %d", r.Summary.NoAuth)
	}
	if r.Summary.MissingTLS != 1 {
		t.Errorf("expected 1 missing_tls, got %d", r.Summary.MissingTLS)
	}
	if r.Summary.ExposedPort != 1 {
		t.Errorf("expected 1 exposed_port, got %d", r.Summary.ExposedPort)
	}
}

func TestFormatTextOutput(t *testing.T) {
	svc := compose.Service{
		Name:        "redis",
		Image:       "redis:7",
		Environment: []string{},
	}
	r := Analyze(makeCollected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "Redis Security Audit") {
		t.Error("expected header in output")
	}
}

func TestIsRedisImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"redis:7", true},
		{"bitnami/redis:6.2", true},
		{"redis/redis-stack:latest", true},
		{"eqalpha/keydb:latest", true},
		{"nginx:latest", false},
		{"postgres:14", false},
	}
	for _, tt := range tests {
		if got := isRedisImage(tt.image); got != tt.want {
			t.Errorf("isRedisImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/my/project"}
	r := Analyze(c)
	if r.Path != "/my/project" {
		t.Errorf("expected path /my/project, got %s", r.Path)
	}
}
