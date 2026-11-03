package secretrotation

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	cf := compose.File{Path: "docker-compose.yml", Services: services}
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{cf}}
}

func TestNoSecrets(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"PORT=8080"}})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestEnvSecret(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"DB_PASSWORD=secret123"}})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "secretrotation_env_secret" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected secretrotation_env_secret finding")
	}
}

func TestHardcodedDefault(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"API_KEY=hardcoded_value_here"}})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "secretrotation_hardcoded_default" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected secretrotation_hardcoded_default finding")
	}
}

func TestVariableRefNotHardcoded(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"DB_PASSWORD=${DB_PASSWORD}"}})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "secretrotation_hardcoded_default" {
				t.Error("should not flag variable reference as hardcoded")
			}
		}
	}
}

func TestStaticCredential(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"SECRET_TOKEN=abc"}})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "secretrotation_static_credential" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected secretrotation_static_credential finding")
	}
}

func TestRotationLabelSuppressesStatic(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "web",
		Environment: []string{"DB_PASSWORD=abc"},
		Labels:      map[string]string{"secret.rotation": "30d"},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "secretrotation_static_credential" {
				t.Error("rotation label should suppress static credential finding")
			}
		}
	}
}

func TestSharedSecret(t *testing.T) {
	svcs := []compose.Service{
		{Name: "svc1", Environment: []string{"DB_PASSWORD=x"}},
		{Name: "svc2", Environment: []string{"DB_PASSWORD=x"}},
		{Name: "svc3", Environment: []string{"DB_PASSWORD=x"}},
		{Name: "svc4", Environment: []string{"DB_PASSWORD=x"}},
	}
	c := mkCollected(svcs...)
	r := Analyze(c)
	if r.Summary.SharedSecret == 0 {
		t.Error("expected shared_secret findings for secret used by >3 services")
	}
}

func TestPrivilegedSecret(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "admin",
		Environment: []string{"API_KEY=secret"},
		Privileged:  true,
	})
	r := Analyze(c)
	if r.Summary.PrivilegedSecret == 0 {
		t.Error("expected secretrotation_privileged_secret finding")
	}
}

func TestNoRotationLabel(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"AUTH_TOKEN=abc"}})
	r := Analyze(c)
	if r.Summary.NoRotationLabel == 0 {
		t.Error("expected secretrotation_no_rotation_label finding")
	}
}

func TestMultipleSecretVars(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "web",
		Environment: []string{"DB_PASSWORD=abc", "API_KEY=def", "SECRET_TOKEN=ghi"},
	})
	r := Analyze(c)
	if r.Summary.EnvSecret < 3 {
		t.Errorf("expected at least 3 env_secret findings, got %d", r.Summary.EnvSecret)
	}
}

func TestNonSecretEnvIgnored(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "web",
		Environment: []string{"PORT=8080", "DEBUG=true", "LOG_LEVEL=info"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for non-secret env vars, got %d", r.Summary.TotalFindings)
	}
}

func TestSummaryTotals(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "a", Environment: []string{"DB_PASSWORD=x"}},
		compose.Service{Name: "b", Environment: []string{"PORT=80"}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"DB_PASSWORD=abc"}})
	r := Analyze(c)
	text := FormatText(r)
	if !containsStr(text, "Secret Rotation") {
		t.Error("expected 'Secret Rotation' in output")
	}
	if !containsStr(text, "web") {
		t.Error("expected service name in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"PORT=80"}})
	r := Analyze(c)
	text := FormatText(r)
	if !containsStr(text, "no findings") {
		t.Error("expected 'no findings' in output")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestCaseInsensitiveSecretDetection(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"db_PASSWORD=abc"}})
	r := Analyze(c)
	if r.Summary.EnvSecret == 0 {
		t.Error("expected case-insensitive detection of secret variable")
	}
}

func TestReportPath(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Path != "/test" {
		t.Errorf("expected path /test, got %s", r.Path)
	}
}

func containsStr(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && contains(s, substr)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
