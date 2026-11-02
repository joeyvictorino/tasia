package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixCommandNoFindings(t *testing.T) {
	dir := t.TempDir()
	err := Run([]string{"fix", "--path", dir})
	if err != nil {
		t.Fatalf("fix returned error: %v", err)
	}
}

func TestFixCommandWithFindings(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    privileged: true
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := Run([]string{"fix", "--path", dir})

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("fix returned error: %v", err)
	}

	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "127.0.0.1") {
		t.Error("fix output should suggest 127.0.0.1 binding for exposed port")
	}
}

func TestFixCommandJSON(t *testing.T) {
	dir := t.TempDir()

	compose := `services:
  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := Run([]string{"fix", "--path", dir, "--format", "json"})

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("fix returned error: %v", err)
	}

	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "rule_id") {
		t.Error("JSON output should contain rule_id field")
	}
	if !strings.Contains(output, "confidence") {
		t.Error("JSON output should contain confidence field")
	}
}
