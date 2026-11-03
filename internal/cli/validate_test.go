package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateValidConfig(t *testing.T) {
	dir := t.TempDir()
	rc := `severities:
  exposed_inference: HIGH
  privileged_container: CRITICAL
`
	if err := os.WriteFile(filepath.Join(dir, ".tasiarc.yaml"), []byte(rc), 0o644); err != nil {
		t.Fatal(err)
	}

	issues := validateRC(dir)
	if len(issues) != 0 {
		t.Errorf("valid config should have no issues, got %d: %v", len(issues), issues)
	}
}

func TestValidateInvalidRuleID(t *testing.T) {
	dir := t.TempDir()
	rc := `severities:
  nonexistent_rule_xyz: HIGH
`
	if err := os.WriteFile(filepath.Join(dir, ".tasiarc.yaml"), []byte(rc), 0o644); err != nil {
		t.Fatal(err)
	}

	issues := validateRC(dir)
	found := false
	for _, i := range issues {
		if i.Severity == "error" && strings.Contains(i.Message, "unknown rule ID") {
			found = true
		}
	}
	if !found {
		t.Error("expected error for unknown rule ID")
	}
}

func TestValidateInvalidSeverity(t *testing.T) {
	dir := t.TempDir()
	rc := `severities:
  exposed_inference: SUPERURGENT
`
	if err := os.WriteFile(filepath.Join(dir, ".tasiarc.yaml"), []byte(rc), 0o644); err != nil {
		t.Fatal(err)
	}

	issues := validateRC(dir)
	found := false
	for _, i := range issues {
		if i.Severity == "error" && strings.Contains(i.Message, "invalid severity") {
			found = true
		}
	}
	if !found {
		t.Error("expected error for invalid severity")
	}
}

func TestValidateUnknownKey(t *testing.T) {
	dir := t.TempDir()
	rc := `severities: {}
bogus_key: true
`
	if err := os.WriteFile(filepath.Join(dir, ".tasiarc.yaml"), []byte(rc), 0o644); err != nil {
		t.Fatal(err)
	}

	issues := validateRC(dir)
	found := false
	for _, i := range issues {
		if i.Severity == "warning" && strings.Contains(i.Message, "unknown key") {
			found = true
		}
	}
	if !found {
		t.Error("expected warning for unknown key")
	}
}

func TestValidateInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".tasiarc.yaml"), []byte("{{[not yaml"), 0o644); err != nil {
		t.Fatal(err)
	}

	issues := validateRC(dir)
	if len(issues) == 0 {
		t.Error("expected error for invalid YAML")
	}
	if issues[0].Severity != "error" {
		t.Error("expected error severity")
	}
}

func TestValidateNoConfig(t *testing.T) {
	dir := t.TempDir()
	issues := validateRC(dir)
	if len(issues) != 0 {
		t.Error("no config file should produce no issues")
	}
}

func TestValidateIgnoreValidFile(t *testing.T) {
	dir := t.TempDir()
	ignore := `# valid entries
exposed_inference
docker-compose.dev.yml
exposed_inference docker-compose.dev.yml
`
	if err := os.WriteFile(filepath.Join(dir, ".tasiaignore"), []byte(ignore), 0o644); err != nil {
		t.Fatal(err)
	}

	issues := validateIgnore(dir)
	errors := 0
	for _, i := range issues {
		if i.Severity == "error" {
			errors++
		}
	}
	if errors > 0 {
		t.Errorf("valid ignore file should have no errors, got %d", errors)
	}
}

func TestValidateIgnoreUnknownRule(t *testing.T) {
	dir := t.TempDir()
	ignore := `fake_rule_that_doesnt_exist
`
	if err := os.WriteFile(filepath.Join(dir, ".tasiaignore"), []byte(ignore), 0o644); err != nil {
		t.Fatal(err)
	}

	issues := validateIgnore(dir)
	found := false
	for _, i := range issues {
		if strings.Contains(i.Message, "unknown rule ID") {
			found = true
		}
	}
	if !found {
		t.Error("expected warning for unknown rule ID in .tasiaignore")
	}
}

func TestValidateIgnoreBadGlob(t *testing.T) {
	dir := t.TempDir()
	ignore := `[invalid-glob
`
	if err := os.WriteFile(filepath.Join(dir, ".tasiaignore"), []byte(ignore), 0o644); err != nil {
		t.Fatal(err)
	}

	issues := validateIgnore(dir)
	found := false
	for _, i := range issues {
		if i.Severity == "error" && strings.Contains(i.Message, "invalid glob") {
			found = true
		}
	}
	if !found {
		t.Error("expected error for invalid glob pattern")
	}
}

func TestValidateNoIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	issues := validateIgnore(dir)
	if len(issues) != 0 {
		t.Error("no ignore file should produce no issues")
	}
}
