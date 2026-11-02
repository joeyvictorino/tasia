package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExplainNoModel(t *testing.T) {
	dir := t.TempDir()
	// Write a minimal compose file so explain has something to scan.
	os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(`
services:
  app:
    image: nginx:latest
`), 0o644)

	err := Run([]string{"explain", "--path", dir})
	if err != nil {
		t.Fatalf("explain without model should succeed: %v", err)
	}

	review := filepath.Join(dir, ".tasia", "LLM_REVIEW.md")
	data, err := os.ReadFile(review)
	if err != nil {
		t.Fatalf("expected LLM_REVIEW.md: %v", err)
	}
	if len(data) == 0 {
		t.Error("LLM_REVIEW.md is empty")
	}
}

func TestExplainEmptyDir(t *testing.T) {
	dir := t.TempDir()
	err := Run([]string{"explain", "--path", dir})
	if err != nil {
		t.Fatalf("explain on empty dir should not error: %v", err)
	}
}

func TestExplainBadOllamaHost(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(`
services:
  app:
    image: nginx:latest
`), 0o644)

	// With an unreachable host and a model name, explain should fail gracefully.
	err := Run([]string{"explain", "--path", dir, "--ollama", "llama3.1", "--ollama-host", "127.0.0.1:19999"})
	if err == nil {
		t.Fatal("explain with unreachable ollama should error")
	}
}
