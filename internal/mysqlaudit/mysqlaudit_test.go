package mysqlaudit

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

func TestIsMySQLImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"mysql:8", true},
		{"mysql:latest", true},
		{"mariadb:10.11", true},
		{"bitnami/mysql:8.0", true},
		{"bitnami/mariadb:10", true},
		{"percona:8.0", true},
		{"nginx:latest", false},
		{"postgres:14", false},
		{"redis:7", false},
	}
	for _, tt := range tests {
		if got := isMySQLImage(tt.image); got != tt.want {
			t.Errorf("isMySQLImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestEmptyRootPassword(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "mysql:8",
		Environment: []string{"MYSQL_ALLOW_EMPTY_PASSWORD=yes"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "empty_root_password" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected empty_root_password finding")
	}
}

func TestEmptyRootPasswordNumeric(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "mysql:8",
		Environment: []string{"MYSQL_ALLOW_EMPTY_PASSWORD=1"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "empty_root_password" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected empty_root_password finding for value '1'")
	}
}

func TestNoEmptyPassword(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "mysql:8",
		Environment: []string{"MYSQL_ALLOW_EMPTY_PASSWORD=no"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "empty_root_password" {
				t.Error("should not flag empty_root_password when set to 'no'")
			}
		}
	}
}

func TestDefaultCredentials(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "mysql:8",
		Environment: []string{"MYSQL_ROOT_PASSWORD=password"},
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

func TestStrongPassword(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "mysql:8",
		Environment: []string{"MYSQL_ROOT_PASSWORD=xK9!mP2@qR7$vN"},
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
		Image:       "mysql:8",
		Environment: []string{"MYSQL_ROOT_PASSWORD=secret"},
		Ports: []compose.PortMapping{
			{HostPort: 3306, TargetPort: 3306, Raw: "3306:3306"},
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
		Image:       "mysql:8",
		Environment: []string{"MYSQL_ROOT_PASSWORD=secret"},
		Ports: []compose.PortMapping{
			{HostPort: 3306, TargetPort: 3306, Raw: "127.0.0.1:3306:3306", HostIP: "127.0.0.1"},
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
		Image:       "mysql:8",
		Environment: []string{"MYSQL_ROOT_PASSWORD=secret"},
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
		Image: "mysql:8",
		Environment: []string{
			"MYSQL_ROOT_PASSWORD=secret",
			"MYSQL_SSL=--ssl-ca=/certs/ca.pem --ssl-cert=/certs/server-cert.pem --ssl-key=/certs/server-key.pem",
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

func TestRandomRootPassword(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "mysql:8",
		Environment: []string{"MYSQL_ROOT_PASSWORD=secret"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "random_root_password" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected random_root_password finding")
	}
}

func TestWithRandomRootPassword(t *testing.T) {
	svc := compose.Service{
		Name:  "db",
		Image: "mysql:8",
		Environment: []string{
			"MYSQL_ROOT_PASSWORD=secret",
			"MYSQL_RANDOM_ROOT_PASSWORD=yes",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "random_root_password" {
				t.Error("should not flag when MYSQL_RANDOM_ROOT_PASSWORD is set")
			}
		}
	}
}

func TestNonMySQLService(t *testing.T) {
	svc := compose.Service{
		Name:  "web",
		Image: "nginx:latest",
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		if len(sr.Findings) > 0 {
			t.Error("non-mysql service should have no findings")
		}
	}
}

func TestMariaDB(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "mariadb:10.11",
		Environment: []string{"MYSQL_ALLOW_EMPTY_PASSWORD=yes"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "empty_root_password" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected MariaDB to be detected as MySQL-like")
	}
}

func TestSummaryCounts(t *testing.T) {
	svc := compose.Service{
		Name:  "db",
		Image: "mysql:8",
		Environment: []string{
			"MYSQL_ALLOW_EMPTY_PASSWORD=yes",
			"MYSQL_ROOT_PASSWORD=password",
		},
		Ports: []compose.PortMapping{
			{HostPort: 3306, TargetPort: 3306, Raw: "3306:3306"},
		},
	}
	r := Analyze(makeCollected(svc))
	if r.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.EmptyRootPassword != 1 {
		t.Errorf("expected 1 empty_root_password, got %d", r.Summary.EmptyRootPassword)
	}
	if r.Summary.DefaultCredentials != 1 {
		t.Errorf("expected 1 default_credentials, got %d", r.Summary.DefaultCredentials)
	}
	if r.Summary.ExposedPort != 1 {
		t.Errorf("expected 1 exposed_port, got %d", r.Summary.ExposedPort)
	}
}

func TestFormatText(t *testing.T) {
	svc := compose.Service{
		Name:        "db",
		Image:       "mysql:8",
		Environment: []string{"MYSQL_ROOT_PASSWORD=secret"},
	}
	r := Analyze(makeCollected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "MySQL Security Audit") {
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
