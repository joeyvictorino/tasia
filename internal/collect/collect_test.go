package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWalkAndCollectCompose(t *testing.T) {
	tmp := t.TempDir()
	cf := filepath.Join(tmp, "docker-compose.yml")
	y := `services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
`
	if err := os.WriteFile(cf, []byte(y), 0644); err != nil {
		t.Fatal(err)
	}
	col, err := WalkAndCollect(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(col.ComposeFiles) != 1 {
		t.Fatalf("expected 1 compose, got %d", len(col.ComposeFiles))
	}
	if len(col.PublishedPorts) == 0 || col.PublishedPorts[0] != 11434 {
		t.Errorf("ports not extracted: %v", col.PublishedPorts)
	}
	if len(col.DetectedRuntimes) == 0 || col.DetectedRuntimes[0] != "ollama" {
		t.Errorf("runtimes not detected: %v", col.DetectedRuntimes)
	}
}

func TestEnvNoValues(t *testing.T) {
	tmp := t.TempDir()
	envp := filepath.Join(tmp, ".env.local")
	if err := os.WriteFile(envp, []byte("HF_TOKEN=hf_abc123\nOTHER=val\nAPI_KEY=sk-xxx\n"), 0644); err != nil {
		t.Fatal(err)
	}
	col, err := WalkAndCollect(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(col.SecretKeyNames) == 0 {
		t.Error("expected secret key names")
	}
	for _, k := range col.SecretKeyNames {
		if k == "hf_abc123" || k == "sk-xxx" {
			t.Errorf("value leaked into key names: %s", k)
		}
	}
	// Ensure relative path (not absolute) for consistency with compose files
	if len(col.EnvFiles) > 0 {
		p := col.EnvFiles[0].Path
		if filepath.IsAbs(p) || strings.Contains(p, tmp) {
			t.Errorf("env path should be relative, got %q", p)
		}
	}
}

func TestMalformedComposeIsRecordedNotSilentlySkipped(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "docker-compose.yml"),
		[]byte("services:\n  ollama:\n    image: [unclosed\n    ports: {{{\n"), 0644); err != nil {
		t.Fatal(err)
	}
	c, err := WalkAndCollect(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ParseErrors) != 1 {
		t.Fatalf("malformed compose must be recorded as a parse error (fail closed), got %d", len(c.ParseErrors))
	}
	if len(c.ComposeFiles) != 0 {
		t.Errorf("malformed compose should not become a parsed compose file")
	}
	if c.ParseErrors[0].Path != "docker-compose.yml" {
		t.Errorf("parse error path = %q, want relative docker-compose.yml", c.ParseErrors[0].Path)
	}
}

func TestLooksLikeSecretValue(t *testing.T) {
	cases := []struct {
		value   string
		pattern string
	}{
		{"sk-1234567890abcdef1234567890abcdef", "sk- prefix (OpenAI/Stripe)"},
		{"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01", "ghp_ prefix (GitHub PAT)"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIA prefix (AWS access key)"},
		{"xoxb-123456789012-1234567890123-AbCd", "xoxb- prefix (Slack bot)"},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJ prefix (JWT/base64 token)"},
		{"0123456789abcdef0123456789abcdef", "hex string >=32 chars"},
		{"hf_ABCDEFGHIJKLMNOPQRSTUVWXyz", "hf_ prefix (Hugging Face)"},
		{"changeme", ""},
		{"hello", ""},
		{"", ""},
		{"TODO", ""},
		{"short", ""},
	}
	for _, tc := range cases {
		got := LooksLikeSecretValue(tc.value)
		if got != tc.pattern {
			t.Errorf("LooksLikeSecretValue(%q) = %q, want %q", tc.value, got, tc.pattern)
		}
	}
}

func TestEnvFileSecretValueDetection(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "env-secrets"))
	if err != nil {
		t.Fatal(err)
	}
	col, err := WalkAndCollect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(col.EnvFiles) == 0 {
		t.Fatal("expected env files from testdata/env-secrets")
	}
	hasValuePattern := false
	for _, ef := range col.EnvFiles {
		for _, key := range ef.Keys {
			if key.ValuePattern != "" {
				hasValuePattern = true
			}
			if strings.Contains(key.ValuePattern, "sk-1234") || strings.Contains(key.ValuePattern, "ghp_ABCDE") {
				t.Errorf("actual value leaked into ValuePattern: %s", key.ValuePattern)
			}
		}
	}
	if !hasValuePattern {
		t.Error("expected at least one key with a ValuePattern from testdata/env-secrets")
	}
}
