package postgresaudit

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

func TestIsPostgresImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"postgres:14", true},
		{"postgres:latest", true},
		{"bitnami/postgresql:15", true},
		{"postgis/postgis:14-3.3", true},
		{"timescale/timescaledb:latest", true},
		{"citusdata/citus:11", true},
		{"nginx:latest", false},
		{"redis:7", false},
		{"mysql:8", false},
	}
	for _, tt := range tests {
		if got := isPostgresImage(tt.image); got != tt.want {
			t.Errorf("isPostgresImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoPassword(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "postgres:14",
		Environment: []string{},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_password" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected no_password finding")
	}
}

func TestWithPassword(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "postgres:14",
		Environment: []string{"POSTGRES_PASSWORD=s3cureP@ss!"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_password" {
				t.Error("should not flag no_password when POSTGRES_PASSWORD is set")
			}
		}
	}
}

func TestTrustAuth(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "postgres:14",
		Environment: []string{"POSTGRES_HOST_AUTH_METHOD=trust"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "trust_auth" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected trust_auth finding")
	}
}

func TestTrustAuthNoPasswordFinding(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "postgres:14",
		Environment: []string{"POSTGRES_HOST_AUTH_METHOD=trust"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_password" {
				t.Error("should not flag no_password when auth method is explicitly set")
			}
		}
	}
}

func TestDefaultCredentials(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "postgres:14",
		Environment: []string{"POSTGRES_PASSWORD=postgres"},
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

func TestStrongCredentials(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "postgres:14",
		Environment: []string{"POSTGRES_PASSWORD=xK9!mP2@qR7$vN"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "default_credentials" {
				t.Error("should not flag default_credentials with a strong password")
			}
		}
	}
}

func TestExposedPort(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "postgres:14",
		Environment: []string{"POSTGRES_PASSWORD=secret"},
		Ports: []compose.PortMapping{
			{HostPort: 5432, TargetPort: 5432, Raw: "5432:5432"},
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

func TestLocalhostPort(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "postgres:14",
		Environment: []string{"POSTGRES_PASSWORD=secret"},
		Ports: []compose.PortMapping{
			{HostPort: 5432, TargetPort: 5432, Raw: "127.0.0.1:5432:5432", HostIP: "127.0.0.1"},
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

func TestNoSSL(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "postgres:14",
		Environment: []string{"POSTGRES_PASSWORD=secret"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_ssl" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected no_ssl finding")
	}
}

func TestWithSSL(t *testing.T) {
	svc := compose.Service{
		Name:  "db",
		Image: "postgres:14",
		Environment: []string{
			"POSTGRES_PASSWORD=secret",
			"PGSSLMODE=require",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_ssl" {
				t.Error("should not flag no_ssl when SSL is configured")
			}
		}
	}
}

func TestSuperuserExposed(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "postgres:14",
		Environment: []string{"POSTGRES_PASSWORD=secret"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "superuser_exposed" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected superuser_exposed finding")
	}
}

func TestCustomUser(t *testing.T) {
	svc := compose.Service{
		Name:  "db",
		Image: "postgres:14",
		Environment: []string{
			"POSTGRES_PASSWORD=secret",
			"POSTGRES_USER=appuser",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "superuser_exposed" {
				t.Error("should not flag superuser_exposed when POSTGRES_USER is set")
			}
		}
	}
}

func TestNonPostgresService(t *testing.T) {
	svc := compose.Service{
		Name:  "web",
		Image: "nginx:latest",
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		if len(sr.Findings) > 0 {
			t.Error("non-postgres service should have no findings")
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "postgres:14",
		Environment: []string{},
		Ports: []compose.PortMapping{
			{HostPort: 5432, TargetPort: 5432, Raw: "5432:5432"},
		},
	}
	r := Analyze(makeCollected(svc))
	if r.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.NoPassword != 1 {
		t.Errorf("expected 1 no_password, got %d", r.Summary.NoPassword)
	}
	if r.Summary.ExposedPort != 1 {
		t.Errorf("expected 1 exposed_port, got %d", r.Summary.ExposedPort)
	}
	if r.Summary.NoSSL != 1 {
		t.Errorf("expected 1 no_ssl, got %d", r.Summary.NoSSL)
	}
	if r.Summary.SuperuserExposed != 1 {
		t.Errorf("expected 1 superuser_exposed, got %d", r.Summary.SuperuserExposed)
	}
}

func TestFormatText(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "postgres:14",
		Environment: []string{},
	}
	r := Analyze(makeCollected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "PostgreSQL Security Audit") {
		t.Error("expected header in output")
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/my/project"}
	r := Analyze(c)
	if r.Path != "/my/project" {
		t.Errorf("expected path /my/project, got %s", r.Path)
	}
}

func TestMultipleServices(t *testing.T) {
	svc1 := compose.Service{
		Name:        "db1",
		Image:       "postgres:14",
		Environment: []string{},
	}
	svc2 := compose.Service{
		Name:  "db2",
		Image: "postgres:15",
		Environment: []string{
			"POSTGRES_PASSWORD=strongpass",
			"POSTGRES_USER=appuser",
			"PGSSLMODE=verify-full",
		},
	}
	r := Analyze(makeCollected(svc1, svc2))
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.NoPassword != 1 {
		t.Errorf("expected 1 no_password, got %d", r.Summary.NoPassword)
	}
}
