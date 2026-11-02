package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTrendsBasic(t *testing.T) {
	dir := t.TempDir()

	run1 := map[string]any{
		"findings": []map[string]any{
			{"id": "docker_socket", "severity": "CRITICAL", "title": "Docker socket", "file": "docker-compose.yml"},
			{"id": "latest_image", "severity": "MEDIUM", "title": "Latest tag", "file": "docker-compose.yml"},
		},
	}
	run2 := map[string]any{
		"findings": []map[string]any{
			{"id": "docker_socket", "severity": "CRITICAL", "title": "Docker socket", "file": "docker-compose.yml"},
		},
	}

	d1, _ := json.Marshal(run1)
	d2, _ := json.Marshal(run2)
	os.WriteFile(filepath.Join(dir, "run1.json"), d1, 0644)
	os.WriteFile(filepath.Join(dir, "run2.json"), d2, 0644)

	err := runTrendsCmd([]string{"--dir", dir})
	if err != nil {
		t.Fatalf("runTrendsCmd: %v", err)
	}
}

func TestTrendsJSON(t *testing.T) {
	dir := t.TempDir()

	run1 := map[string]any{
		"findings": []map[string]any{
			{"id": "docker_socket", "severity": "CRITICAL", "title": "Docker socket", "file": "dc.yml"},
		},
	}
	d1, _ := json.Marshal(run1)
	os.WriteFile(filepath.Join(dir, "run1.json"), d1, 0644)

	err := runTrendsCmd([]string{"--dir", dir, "--format", "json"})
	if err != nil {
		t.Fatalf("runTrendsCmd json: %v", err)
	}
}

func TestTrendsMissingDir(t *testing.T) {
	err := runTrendsCmd([]string{})
	if err == nil {
		t.Fatal("expected error for missing --dir")
	}
}

func TestTrendsEmptyDir(t *testing.T) {
	dir := t.TempDir()
	err := runTrendsCmd([]string{"--dir", dir})
	if err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestTrendsNewFindingTracking(t *testing.T) {
	dir := t.TempDir()

	run1 := map[string]any{
		"findings": []map[string]any{
			{"id": "docker_socket", "severity": "CRITICAL", "title": "Docker socket", "file": "dc.yml"},
		},
	}
	run2 := map[string]any{
		"findings": []map[string]any{
			{"id": "docker_socket", "severity": "CRITICAL", "title": "Docker socket", "file": "dc.yml"},
			{"id": "latest_image", "severity": "MEDIUM", "title": "Latest tag", "file": "dc.yml"},
		},
	}

	d1, _ := json.Marshal(run1)
	d2, _ := json.Marshal(run2)
	os.WriteFile(filepath.Join(dir, "01_run.json"), d1, 0644)
	os.WriteFile(filepath.Join(dir, "02_run.json"), d2, 0644)

	err := runTrendsCmd([]string{"--dir", dir, "--format", "json"})
	if err != nil {
		t.Fatalf("runTrendsCmd: %v", err)
	}
}
