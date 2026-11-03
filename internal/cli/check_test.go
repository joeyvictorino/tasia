package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckPass(t *testing.T) {
	dir := t.TempDir()
	compose := `services:
  web:
    image: nginx:1.25
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := Run([]string{"check", "--path", dir, "--fail-on", "critical"})
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("check returned error: %v", err)
	}
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])
	if !strings.Contains(output, "PASS") {
		t.Errorf("expected PASS in output, got: %s", output)
	}
}

func TestCheckJSON(t *testing.T) {
	dir := t.TempDir()
	compose := `services:
  web:
    image: nginx:1.25
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := Run([]string{"check", "--path", dir, "--fail-on", "critical", "--format", "json"})
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("check returned error: %v", err)
	}
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	var result map[string]any
	if err := json.Unmarshal(buf[:n], &result); err != nil {
		t.Fatalf("not valid JSON: %v\noutput: %s", err, string(buf[:n]))
	}
	if result["pass"] != true {
		t.Errorf("expected pass=true, got %v", result["pass"])
	}
}

func TestCheckNoArgs(t *testing.T) {
	dir := t.TempDir()
	err := Run([]string{"check", "--path", dir})
	if err != nil {
		t.Fatalf("check on empty dir should not error: %v", err)
	}
}
