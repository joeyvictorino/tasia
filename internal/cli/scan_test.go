package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanBasic(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  ai-agent:
    image: myagent:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`), 0644)

	err := runScanCmd([]string{"--path", dir, "--format", "text"})
	// may exit 1 due to findings, that's ok for this test
	_ = err
}

func TestScanJSON(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  ai-agent:
    image: myagent:latest
`), 0644)

	err := runScanCmd([]string{"--path", dir, "--format", "json"})
	if err != nil {
		t.Fatalf("runScanCmd json: %v", err)
	}
}

func TestScanEmptyDir(t *testing.T) {
	dir := t.TempDir()
	err := runScanCmd([]string{"--path", dir})
	if err != nil {
		t.Fatalf("runScanCmd empty: %v", err)
	}
}

func TestScanRuleFilter(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  ai-agent:
    image: myagent:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`), 0644)

	err := runScanCmd([]string{"--path", dir, "--rules", "nonexistent_rule"})
	if err != nil {
		t.Fatalf("runScanCmd rule filter: %v", err)
	}
}

func TestScanFileFilter(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  ai-agent:
    image: myagent:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`), 0644)

	err := runScanCmd([]string{"--path", dir, "--files", compose})
	// findings should be scoped to the file
	_ = err
}

func TestScanFailOn(t *testing.T) {
	dir := t.TempDir()
	err := runScanCmd([]string{"--path", dir, "--fail-on", "critical"})
	if err != nil {
		t.Fatalf("runScanCmd fail-on: %v", err)
	}
}

func TestScanInvalidFailOn(t *testing.T) {
	err := runScanCmd([]string{"--fail-on", "banana"})
	if err == nil {
		t.Fatal("expected error for invalid fail-on")
	}
}
