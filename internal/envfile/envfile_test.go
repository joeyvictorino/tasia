package envfile

import (
	"encoding/json"
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

func hasRule(sr ServiceResult, rule string) bool {
	for _, f := range sr.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestHardcodedSecret(t *testing.T) {
	c := collected(compose.Service{
		Name:        "db",
		Environment: []string{"MYSQL_ROOT_PASSWORD=supersecret123"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "envfile_hardcoded_secret") {
		t.Error("expected envfile_hardcoded_secret for MYSQL_ROOT_PASSWORD")
	}
	if r.Summary.HardcodedSecrets != 1 {
		t.Errorf("expected 1 hardcoded secret, got %d", r.Summary.HardcodedSecrets)
	}
}

func TestAPIKeySecret(t *testing.T) {
	c := collected(compose.Service{
		Name:        "app",
		Environment: []string{"API_KEY=sk-abc123def456"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "envfile_hardcoded_secret") {
		t.Error("expected envfile_hardcoded_secret for API_KEY")
	}
}

func TestEmptyPassword(t *testing.T) {
	c := collected(compose.Service{
		Name:        "db",
		Environment: []string{"MYSQL_ROOT_PASSWORD="},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "envfile_empty_password") {
		t.Error("expected envfile_empty_password for empty MYSQL_ROOT_PASSWORD")
	}
	if r.Summary.EmptyPasswords != 1 {
		t.Errorf("expected 1 empty password, got %d", r.Summary.EmptyPasswords)
	}
}

func TestDebugEnabled(t *testing.T) {
	c := collected(compose.Service{
		Name:        "app",
		Environment: []string{"DEBUG=true"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "envfile_debug_enabled") {
		t.Error("expected envfile_debug_enabled for DEBUG=true")
	}
	if r.Summary.DebugEnabled != 1 {
		t.Errorf("expected 1 debug enabled, got %d", r.Summary.DebugEnabled)
	}
}

func TestNodeEnvDevelopment(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		Environment: []string{"NODE_ENV=development"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "envfile_debug_enabled") {
		t.Error("expected envfile_debug_enabled for NODE_ENV=development")
	}
}

func TestNonSecretEnvSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:        "app",
		Environment: []string{"PORT=8080", "LOG_LEVEL=info"},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings for non-secret env vars, got %d", len(r.Services[0].Findings))
	}
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{Name: "clean"})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for clean service, got %d", len(r.Services[0].Findings))
	}
}

func TestProductionNodeEnvSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		Environment: []string{"NODE_ENV=production"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "envfile_debug_enabled") {
		t.Error("should not flag NODE_ENV=production as debug mode")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleViolations(t *testing.T) {
	c := collected(compose.Service{
		Name:        "allbad",
		Environment: []string{"PASSWORD=secret", "DEBUG=1", "API_KEY="},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{
		Name:        "app",
		Environment: []string{"PASSWORD=secret"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		Environment: []string{"SECRET=abc"},
	})
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var r2 Report
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if r2.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service after round-trip, got %d", r2.Summary.TotalServices)
	}
}
