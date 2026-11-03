package envexpand

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: svcs},
		},
	}
}

func TestNoEnvVars(t *testing.T) {
	c := makeCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestShellExpansion(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"DB_HOST=$(hostname -f)"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "envexpand_shell_expansion" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected envexpand_shell_expansion finding")
	}
}

func TestBacktickInjection(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"HOST=`hostname`"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "envexpand_backtick_injection" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected envexpand_backtick_injection finding")
	}
}

func TestNestedInterpolation(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"URL=${PROTO:-${DEFAULT_PROTO}}://host"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "envexpand_nested_interpolation" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected envexpand_nested_interpolation finding")
	}
}

func TestEmptyDefault(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"TOKEN=${AUTH_TOKEN:-}"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "envexpand_empty_default" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected envexpand_empty_default finding")
	}
}

func TestSecretInEnv(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"PASSWORD=hunter2"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "envexpand_secret_in_env" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected envexpand_secret_in_env finding")
	}
}

func TestSecretViaRef(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"PASSWORD=${DB_PASS}"},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "envexpand_secret_in_env" {
				t.Error("should not flag secret when value is a variable reference")
			}
		}
	}
}

func TestComplexExpansion(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"URL=${PROTO}://${HOST}:${PORT}/${PATH}"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "envexpand_unquoted_expansion" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected envexpand_unquoted_expansion finding for 4 expansions")
	}
}

func TestSimpleExpansionOK(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"DB_HOST=${DATABASE_HOST}"},
	})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "envexpand_unquoted_expansion" {
				t.Error("should not flag single variable expansion as complex")
			}
		}
	}
}

func TestNoValueSkipped(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"DEBUG"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for key-only env, got %d", r.Summary.TotalFindings)
	}
}

func TestApiKeySecret(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"API_KEY=sk-abc123def456"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "envexpand_secret_in_env" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected envexpand_secret_in_env finding for API_KEY")
	}
}

func TestTokenSecret(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"AUTH_TOKEN=eyJhbGciOiJIUzI1NiJ9"},
	})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "envexpand_secret_in_env" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected envexpand_secret_in_env finding for AUTH_TOKEN")
	}
}

func TestMultipleServices(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", Environment: []string{"PASSWORD=pass1"}},
		compose.Service{Name: "b", Environment: []string{"HOST=$(hostname)"}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestSummary(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", Environment: []string{"X=$(cmd)"}},
		compose.Service{Name: "b", Environment: []string{"Y=`cmd`"}},
	)
	r := Analyze(c)
	if r.Summary.ShellExpansion != 1 {
		t.Errorf("expected 1 shell expansion, got %d", r.Summary.ShellExpansion)
	}
	if r.Summary.BacktickInjection != 1 {
		t.Errorf("expected 1 backtick injection, got %d", r.Summary.BacktickInjection)
	}
}

func TestFormatText(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"X=$(cmd)"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !strings.Contains(text, "Environment Variable") {
		t.Error("expected header in text output")
	}
}

func TestEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/empty"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestSafeEnvNormal(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"PORT=8080", "DEBUG=true", "NODE_ENV=production"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for safe env vars, got %d", r.Summary.TotalFindings)
	}
}

func TestShellExpansionNested(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "app",
		Environment: []string{"PATH=$(echo /usr/bin):$(echo /usr/local/bin)"},
	})
	r := Analyze(c)
	if r.Summary.ShellExpansion < 1 {
		t.Error("expected at least 1 shell expansion finding")
	}
}
