package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSummaryBasic(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  ai-agent:
    image: myagent:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`), 0644)

	err := runSummaryCmd([]string{"--path", dir})
	if err != nil {
		t.Fatalf("runSummaryCmd: %v", err)
	}
}

func TestSummaryJSON(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  ai-agent:
    image: myagent:latest
`), 0644)

	err := runSummaryCmd([]string{"--path", dir, "--format", "json"})
	if err != nil {
		t.Fatalf("runSummaryCmd json: %v", err)
	}
}

func TestSummaryEmptyDir(t *testing.T) {
	dir := t.TempDir()
	err := runSummaryCmd([]string{"--path", dir})
	if err != nil {
		t.Fatalf("runSummaryCmd empty: %v", err)
	}
}

func TestSummaryTopN(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`
services:
  ai-agent:
    image: myagent:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`), 0644)

	err := runSummaryCmd([]string{"--path", dir, "--top", "1"})
	if err != nil {
		t.Fatalf("runSummaryCmd top: %v", err)
	}
}
