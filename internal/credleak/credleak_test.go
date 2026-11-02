package credleak

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

func hasRule(sr ServiceResult, rule string) bool {
	for _, f := range sr.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		Environment: []string{"NODE_ENV=production"},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings for clean service, got %d", len(r.Services[0].Findings))
	}
}

func TestHardcodedPassword(t *testing.T) {
	c := collected(compose.Service{
		Name:        "db",
		Environment: []string{"PASSWORD=hunter2"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "credleak_env_hardcoded") {
		t.Error("expected credleak_env_hardcoded for hardcoded password")
	}
}

func TestAPIKeyInEnv(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		Environment: []string{"API_KEY=sk-1234567890abcdef"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "credleak_env_hardcoded") {
		t.Error("expected credleak_env_hardcoded for API key")
	}
}

func TestVariableReferenceIsSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		Environment: []string{"PASSWORD=${DB_PASSWORD}"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "credleak_env_hardcoded") {
		t.Error("variable reference should not be flagged")
	}
}

func TestEnvVarReferenceIsSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		Environment: []string{"SECRET_KEY=$SECRET_FROM_ENV"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "credleak_env_hardcoded") {
		t.Error("env var reference should not be flagged")
	}
}

func TestCommandSecret(t *testing.T) {
	c := collected(compose.Service{
		Name:    "worker",
		Command: []string{"--password=s3cret123"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "credleak_command_secret") {
		t.Error("expected credleak_command_secret for password in command")
	}
}

func TestLabelSecret(t *testing.T) {
	c := collected(compose.Service{
		Name:   "web",
		Labels: map[string]string{"deploy.api_key": "realkey123"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "credleak_label_secret") {
		t.Error("expected credleak_label_secret for credential in label")
	}
}

func TestSummary(t *testing.T) {
	c := collected(
		compose.Service{Name: "clean", Environment: []string{"FOO=bar"}},
		compose.Service{Name: "leaky", Environment: []string{"PASSWORD=secret"}},
	)
	r := Analyze(c)
	if r.Summary.LeakyServices != 1 {
		t.Errorf("expected 1 leaky service, got %d", r.Summary.LeakyServices)
	}
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 total services, got %d", r.Summary.TotalServices)
	}
}

func TestAWSSecret(t *testing.T) {
	c := collected(compose.Service{
		Name:        "worker",
		Environment: []string{"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "credleak_env_hardcoded") {
		t.Error("expected credleak_env_hardcoded for AWS secret key")
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{
		Name:        "web",
		Environment: []string{"PASSWORD=secret"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("FormatText should produce output")
	}
}
