package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseEmpty(t *testing.T) {
	c, err := parse([]byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Severities) != 0 {
		t.Errorf("expected 0 severities, got %d", len(c.Severities))
	}
}

func TestParseSeverities(t *testing.T) {
	yaml := `
severities:
  exposed_inference: medium
  latest_image: LOW
  docker_socket_mount: CRITICAL
`
	c, err := parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Severities) != 3 {
		t.Fatalf("expected 3 severities, got %d", len(c.Severities))
	}
	if c.SeverityFor("exposed_inference") != "MEDIUM" {
		t.Errorf("exposed_inference: got %q", c.SeverityFor("exposed_inference"))
	}
	if c.SeverityFor("latest_image") != "LOW" {
		t.Errorf("latest_image: got %q", c.SeverityFor("latest_image"))
	}
	if c.SeverityFor("docker_socket_mount") != "CRITICAL" {
		t.Errorf("docker_socket_mount: got %q", c.SeverityFor("docker_socket_mount"))
	}
}

func TestSeverityForMissing(t *testing.T) {
	c := &Config{Severities: map[string]string{"exposed_inference": "LOW"}}
	if got := c.SeverityFor("nonexistent"); got != "" {
		t.Errorf("nonexistent rule should return empty, got %q", got)
	}
}

func TestSeverityForNilConfig(t *testing.T) {
	var c *Config
	if got := c.SeverityFor("anything"); got != "" {
		t.Errorf("nil config should return empty, got %q", got)
	}
}

func TestValidSeverity(t *testing.T) {
	for _, s := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if !ValidSeverity(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []string{"", "WARN", "INFO", "critical"} {
		if ValidSeverity(s) {
			t.Errorf("%q should not be valid", s)
		}
	}
}

func TestLoadMissing(t *testing.T) {
	c, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Severities) != 0 {
		t.Error("missing config should give empty severities")
	}
}

func TestLoadPresent(t *testing.T) {
	dir := t.TempDir()
	content := []byte("severities:\n  latest_image: low\n")
	if err := os.WriteFile(filepath.Join(dir, ".tasiarc.yaml"), content, 0644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.SeverityFor("latest_image") != "LOW" {
		t.Errorf("latest_image: got %q, want LOW", c.SeverityFor("latest_image"))
	}
}

func TestLoadYmlExtension(t *testing.T) {
	dir := t.TempDir()
	content := []byte("severities:\n  exposed_ui: critical\n")
	if err := os.WriteFile(filepath.Join(dir, ".tasiarc.yml"), content, 0644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.SeverityFor("exposed_ui") != "CRITICAL" {
		t.Errorf("exposed_ui: got %q, want CRITICAL", c.SeverityFor("exposed_ui"))
	}
}
