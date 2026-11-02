package cli

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestBuildEnvAuditEmpty(t *testing.T) {
	c := &collect.Collected{}
	r := buildEnvAudit(c)
	if r.TotalVars != 0 {
		t.Errorf("expected 0 vars, got %d", r.TotalVars)
	}
}

func TestBuildEnvAuditFromCompose(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "/tmp/docker-compose.yml",
				Services: []compose.Service{
					{Name: "app", Environment: []string{"DATABASE_URL=postgres://...", "API_KEY=secret123"}},
					{Name: "worker", Environment: []string{"DATABASE_URL=postgres://...", "LOG_LEVEL=debug"}},
				},
			},
		},
	}
	r := buildEnvAudit(c)
	if r.TotalVars != 3 {
		t.Errorf("expected 3 vars, got %d", r.TotalVars)
	}
	if r.SecretCount != 1 {
		t.Errorf("expected 1 secret, got %d", r.SecretCount)
	}
	if r.MultiCount != 1 {
		t.Errorf("expected 1 multi-source, got %d", r.MultiCount)
	}
}

func TestEnvNameParsing(t *testing.T) {
	tests := []struct{ input, want string }{
		{"FOO=bar", "FOO"},
		{"BAZ", "BAZ"},
		{"KEY=", "KEY"},
		{"=bad", ""},
	}
	for _, tt := range tests {
		got := envName(tt.input)
		if got != tt.want {
			t.Errorf("envName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSecretPatternMatching(t *testing.T) {
	secrets := []string{"API_KEY", "DB_PASSWORD", "AUTH_TOKEN", "PRIVATE_KEY", "SECRET_VALUE"}
	normals := []string{"DATABASE_URL", "LOG_LEVEL", "PORT", "HOST", "DEBUG"}

	for _, s := range secrets {
		if !secretPatterns.MatchString(s) {
			t.Errorf("%s should match secret pattern", s)
		}
	}
	for _, s := range normals {
		if secretPatterns.MatchString(s) {
			t.Errorf("%s should not match secret pattern", s)
		}
	}
}

func TestFormatEnvAuditText(t *testing.T) {
	r := envAuditResult{
		TotalVars:   3,
		SecretCount: 1,
		MultiCount:  1,
		Variables: []envVarEntry{
			{Name: "API_KEY", Sources: []string{"env:.env"}, LooksSecret: true},
			{Name: "PORT", Sources: []string{"compose:docker-compose.yml(app)"}, LooksSecret: false},
		},
	}
	text := formatEnvAuditText(r)
	if !strings.Contains(text, "Environment Variable Audit") {
		t.Error("missing header")
	}
	if !strings.Contains(text, "API_KEY") {
		t.Error("missing secret var")
	}
	if !strings.Contains(text, "Secret-looking: 1") {
		t.Error("missing secret count")
	}
}

func TestEnvAuditSortedKeys(t *testing.T) {
	m := map[string]bool{"c": true, "a": true, "b": true}
	got := envAuditSortedKeys(m)
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("expected sorted [a b c], got %v", got)
	}
}
