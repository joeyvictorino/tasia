package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestSuggestEmpty(t *testing.T) {
	dir := t.TempDir()
	err := runSuggest([]string{"--path", dir})
	if err != nil {
		t.Fatalf("suggest empty: %v", err)
	}
}

func TestSuggestJSON(t *testing.T) {
	dir := t.TempDir()
	err := runSuggest([]string{"--path", dir, "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSuggestWithFindings(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  ai-agent:
    image: myagent:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`), 0644)

	err := runSuggest([]string{"--path", dir, "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSuggestSeverityFilter(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  ai-agent:
    image: myagent:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`), 0644)

	err := runSuggest([]string{"--path", dir, "--severity", "critical"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBuildSuggestion(t *testing.T) {
	f := rules.Finding{
		ID:       "exposed_port",
		Severity: rules.SeverityHigh,
		Title:    "Port exposed",
		File:     "docker-compose.yml",
		Line:     5,
		Fix:      "Bind to 127.0.0.1",
	}
	s := buildSuggestion(f)
	if s.Effort != "medium" {
		t.Fatalf("expected medium effort, got %s", s.Effort)
	}
	if len(s.Actions) == 0 {
		t.Fatal("expected actions")
	}
}
