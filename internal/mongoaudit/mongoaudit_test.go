package mongoaudit

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

func TestNoAuth(t *testing.T) {
	svc := compose.Service{Name: "mongo", Image: "mongo:6", Environment: []string{}}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_auth" { found = true }
		}
	}
	if !found { t.Error("expected no_auth finding") }
}

func TestWithAuth(t *testing.T) {
	svc := compose.Service{
		Name: "mongo", Image: "mongo:6",
		Environment: []string{"MONGO_INITDB_ROOT_USERNAME=admin", "MONGO_INITDB_ROOT_PASSWORD=s3cureP@ss"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_auth" { t.Error("should not flag when auth is configured") }
		}
	}
}

func TestDefaultCredentials(t *testing.T) {
	svc := compose.Service{
		Name: "mongo", Image: "mongo:6",
		Environment: []string{"MONGO_INITDB_ROOT_USERNAME=admin", "MONGO_INITDB_ROOT_PASSWORD=admin"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "default_credentials" { found = true }
		}
	}
	if !found { t.Error("expected default_credentials finding") }
}

func TestStrongCredentials(t *testing.T) {
	svc := compose.Service{
		Name: "mongo", Image: "mongo:6",
		Environment: []string{"MONGO_INITDB_ROOT_USERNAME=dbadmin", "MONGO_INITDB_ROOT_PASSWORD=xK9!mZ2@pQ7wL4"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "default_credentials" { t.Error("should not flag strong credentials") }
		}
	}
}

func TestExposedPort(t *testing.T) {
	svc := compose.Service{
		Name: "mongo", Image: "mongo:6",
		Ports: []compose.PortMapping{{HostPort: 27017, TargetPort: 27017, Raw: "27017:27017"}},
		Environment: []string{"MONGO_INITDB_ROOT_USERNAME=admin", "MONGO_INITDB_ROOT_PASSWORD=s3cure"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_port" { found = true }
		}
	}
	if !found { t.Error("expected exposed_port finding") }
}

func TestLocalhostPort(t *testing.T) {
	svc := compose.Service{
		Name: "mongo", Image: "mongo:6",
		Ports: []compose.PortMapping{{HostPort: 27017, TargetPort: 27017, Raw: "127.0.0.1:27017:27017", HostIP: "127.0.0.1"}},
		Environment: []string{"MONGO_INITDB_ROOT_USERNAME=admin", "MONGO_INITDB_ROOT_PASSWORD=s3cure"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_port" { t.Error("should not flag port bound to localhost") }
		}
	}
}

func TestNoTLS(t *testing.T) {
	svc := compose.Service{
		Name: "mongo", Image: "mongo:6",
		Environment: []string{"MONGO_INITDB_ROOT_USERNAME=admin", "MONGO_INITDB_ROOT_PASSWORD=s3cure"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_tls" { found = true }
		}
	}
	if !found { t.Error("expected no_tls finding") }
}

func TestWithTLS(t *testing.T) {
	svc := compose.Service{
		Name: "mongo", Image: "mongo:6",
		Environment: []string{"MONGO_INITDB_ROOT_USERNAME=admin", "MONGO_INITDB_ROOT_PASSWORD=s3cure", "MONGODB_TLS_ENABLED=true"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_tls" { t.Error("should not flag when TLS is configured") }
		}
	}
}

func TestWithTLSCommand(t *testing.T) {
	svc := compose.Service{
		Name: "mongo", Image: "mongo:6",
		Command: []string{"mongod", "--tlsMode", "requireTLS"},
		Environment: []string{"MONGO_INITDB_ROOT_USERNAME=admin", "MONGO_INITDB_ROOT_PASSWORD=s3cure"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_tls" { t.Error("should not flag when TLS is in command") }
		}
	}
}

func TestBindAllWithoutAuth(t *testing.T) {
	svc := compose.Service{Name: "mongo", Image: "mongo:6", Command: []string{"mongod", "--bind_ip_all"}}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "bind_all_interfaces" { found = true }
		}
	}
	if !found { t.Error("expected bind_all_interfaces finding") }
}

func TestBindAllWithAuth(t *testing.T) {
	svc := compose.Service{
		Name: "mongo", Image: "mongo:6",
		Command: []string{"mongod", "--bind_ip_all", "--auth"},
		Environment: []string{"MONGO_INITDB_ROOT_USERNAME=admin", "MONGO_INITDB_ROOT_PASSWORD=s3cure"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "bind_all_interfaces" { t.Error("should not flag bind_all when auth is present") }
		}
	}
}

func TestNonMongoService(t *testing.T) {
	svc := compose.Service{Name: "nginx", Image: "nginx:latest"}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		if len(sr.Findings) > 0 { t.Error("non-mongo service should have no findings") }
	}
}

func TestBitnamiMongo(t *testing.T) {
	svc := compose.Service{Name: "db", Image: "bitnami/mongodb:6.0", Environment: []string{}}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_auth" { found = true }
		}
	}
	if !found { t.Error("expected bitnami/mongodb to be detected") }
}

func TestSummaryCounts(t *testing.T) {
	svc := compose.Service{
		Name: "mongo", Image: "mongo:6",
		Ports: []compose.PortMapping{{HostPort: 27017, TargetPort: 27017, Raw: "27017:27017"}},
	}
	r := Analyze(makeCollected(svc))
	if r.Summary.TotalServices != 1 { t.Errorf("expected 1 service, got %d", r.Summary.TotalServices) }
	if r.Summary.NoAuth != 1 { t.Errorf("expected 1 no_auth, got %d", r.Summary.NoAuth) }
	if r.Summary.ExposedPort != 1 { t.Errorf("expected 1 exposed_port, got %d", r.Summary.ExposedPort) }
	if r.Summary.NoTLS != 1 { t.Errorf("expected 1 no_tls, got %d", r.Summary.NoTLS) }
}

func TestFormatTextOutput(t *testing.T) {
	svc := compose.Service{Name: "mongo", Image: "mongo:6", Environment: []string{}}
	r := Analyze(makeCollected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "MongoDB Security Audit") { t.Error("expected header in output") }
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/my/project"}
	r := Analyze(c)
	if r.Path != "/my/project" { t.Errorf("expected path /my/project, got %s", r.Path) }
}

func TestIsMongoImage(t *testing.T) {
	tests := []struct { image string; want bool }{
		{"mongo:6", true}, {"bitnami/mongodb:6.0", true},
		{"percona/percona-server-mongodb:6", true},
		{"nginx:latest", false}, {"redis:7", false},
	}
	for _, tt := range tests {
		if got := isMongoImage(tt.image); got != tt.want {
			t.Errorf("isMongoImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestAuthViaCommand(t *testing.T) {
	svc := compose.Service{Name: "mongo", Image: "mongo:6", Command: []string{"mongod", "--auth"}}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_auth" { t.Error("should detect --auth in command") }
		}
	}
}

func TestMultipleServices(t *testing.T) {
	svc1 := compose.Service{Name: "mongo1", Image: "mongo:6", Environment: []string{}}
	svc2 := compose.Service{
		Name: "mongo2", Image: "mongo:6",
		Environment: []string{"MONGO_INITDB_ROOT_USERNAME=admin", "MONGO_INITDB_ROOT_PASSWORD=xK9!mZ2@", "MONGODB_TLS_ENABLED=true"},
	}
	r := Analyze(makeCollected(svc1, svc2))
	if r.Summary.TotalServices != 2 { t.Errorf("expected 2 services, got %d", r.Summary.TotalServices) }
	if r.Summary.NoAuth != 1 { t.Errorf("expected 1 no_auth, got %d", r.Summary.NoAuth) }
}
