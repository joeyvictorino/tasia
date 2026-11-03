package mongoaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func coll(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root:         "/test",
		ComposeFiles: []compose.File{{Services: services}},
	}
}

func TestIsMongoImage(t *testing.T) {
	tests := []struct{ img string; want bool }{
		{"mongo:6", true},
		{"bitnami/mongodb:latest", true},
		{"nginx:latest", false},
		{"MONGO:7", true},
	}
	for _, tc := range tests {
		if got := isMongoImage(tc.img); got != tc.want {
			t.Errorf("isMongoImage(%q) = %v, want %v", tc.img, got, tc.want)
		}
	}
}

func TestNoAuth(t *testing.T) {
	envs := []string{"AUTH=false"}
	if !hasNoAuth(envs, nil) {
		t.Error("expected no auth detected")
	}
}

func TestNoAuthCommand(t *testing.T) {
	cmd := []string{"mongod", "--noauth"}
	if !hasNoAuth(nil, cmd) {
		t.Error("expected --noauth detected")
	}
}

func TestAuthEnabled(t *testing.T) {
	envs := []string{"MONGO_INITDB_ROOT_USERNAME=admin"}
	if hasNoAuth(envs, nil) {
		t.Error("auth should be detected as enabled")
	}
}

func TestDefaultCredentials(t *testing.T) {
	envs := []string{"MONGO_INITDB_ROOT_PASSWORD=admin"}
	if !hasDefaultCredentials(envs) {
		t.Error("expected default credentials")
	}
}

func TestStrongCredentials(t *testing.T) {
	envs := []string{"MONGO_INITDB_ROOT_PASSWORD=sup3rStr0ng!"}
	if hasDefaultCredentials(envs) {
		t.Error("strong password should not trigger")
	}
}

func TestNoTLS(t *testing.T) {
	envs := []string{"TLS=false"}
	if !hasNoTLS(envs) {
		t.Error("expected no TLS")
	}
}

func TestBindAllInterfaces(t *testing.T) {
	envs := []string{"BIND_IP_ALL=true"}
	if !hasBindAllInterfaces(envs, nil) {
		t.Error("expected bind all detected")
	}
}

func TestBindAllCommand(t *testing.T) {
	cmd := []string{"mongod", "--bind_ip_all"}
	if !hasBindAllInterfaces(nil, cmd) {
		t.Error("expected --bind_ip_all detected")
	}
}

func TestScriptingEnabled(t *testing.T) {
	envs := []string{"SCRIPTING=true"}
	if !hasScriptingEnabled(envs) {
		t.Error("expected scripting detected")
	}
}

func TestExposedPort(t *testing.T) {
	svc := compose.Service{
		Name:  "db",
		Image: "mongo:6",
		Ports: []compose.PortMapping{{HostPort: 27017, TargetPort: 27017, HostIP: ""}},
	}
	sr := analyzeService(svc)
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "mongo_exposed_port" {
			found = true
		}
	}
	if !found {
		t.Error("expected exposed port finding")
	}
}

func TestBoundPort(t *testing.T) {
	svc := compose.Service{
		Name:  "db",
		Image: "mongo",
		Ports: []compose.PortMapping{{HostPort: 27017, TargetPort: 27017, HostIP: "127.0.0.1"}},
	}
	sr := analyzeService(svc)
	for _, f := range sr.Findings {
		if f.Rule == "mongo_exposed_port" {
			t.Error("localhost-bound port should not trigger")
		}
	}
}

func TestCleanService(t *testing.T) {
	svc := compose.Service{Name: "db", Image: "mongo"}
	sr := analyzeService(svc)
	if len(sr.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(sr.Findings))
	}
}

func TestAnalyzeSkipsNonMongo(t *testing.T) {
	c := coll(compose.Service{Name: "web", Image: "nginx"})
	r := Analyze(c)
	if len(r.Services) != 0 {
		t.Error("should skip non-mongo services")
	}
}

func TestAnalyzeSummary(t *testing.T) {
	c := coll(compose.Service{
		Name:        "db",
		Image:       "mongo",
		Environment: []string{"MONGO_INITDB_ROOT_PASSWORD=admin"},
		Command:     []string{"mongod", "--noauth"},
	})
	r := Analyze(c)
	if r.Summary.NoAuth < 1 {
		t.Error("expected no auth in summary")
	}
	if r.Summary.DefaultCredentials < 1 {
		t.Error("expected default creds in summary")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Report{Path: "/test"}
	text := FormatText(r)
	if !strings.Contains(text, "No MongoDB") {
		t.Error("should say no MongoDB services")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	c := coll(compose.Service{
		Name:        "db",
		Image:       "mongo",
		Environment: []string{"MONGO_INITDB_ROOT_PASSWORD=admin"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "mongo_default_credentials") {
		t.Error("format should include finding rule")
	}
}
