package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLintCleanConfig(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".tasiarc.yaml"), []byte(`severities:
  exposed_inference: HIGH
`), 0o644)

	err := Run([]string{"lint", "--path", dir})
	if err != nil {
		t.Fatalf("lint should pass on clean config: %v", err)
	}
}

func TestLintUnknownKey(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".tasiarc.yaml"), []byte(`bogus_key: true
severities:
  exposed_inference: HIGH
`), 0o644)

	err := Run([]string{"lint", "--path", dir})
	if err == nil {
		t.Fatal("lint should fail on unknown key")
	}
}

func TestLintInvalidSeverity(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".tasiarc.yaml"), []byte(`severities:
  exposed_inference: EXTREME
`), 0o644)

	err := Run([]string{"lint", "--path", dir})
	if err == nil {
		t.Fatal("lint should fail on invalid severity")
	}
}

func TestLintCustomRulesDuplicateID(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".tasia"), 0o755)
	os.WriteFile(filepath.Join(dir, ".tasia", "rules.yaml"), []byte(`rules:
  - id: custom_test
    pattern: "foo"
    severity: HIGH
  - id: custom_test
    pattern: "bar"
    severity: LOW
`), 0o644)

	err := Run([]string{"lint", "--path", dir})
	if err == nil {
		t.Fatal("lint should fail on duplicate rule ID")
	}
}

func TestLintCustomRulesInvalidRegex(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".tasia"), 0o755)
	os.WriteFile(filepath.Join(dir, ".tasia", "rules.yaml"), []byte(`rules:
  - id: custom_bad
    pattern: "[invalid"
    severity: HIGH
`), 0o644)

	err := Run([]string{"lint", "--path", dir})
	if err == nil {
		t.Fatal("lint should fail on invalid regex")
	}
}

func TestLintCustomRulesMissingPattern(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".tasia"), 0o755)
	os.WriteFile(filepath.Join(dir, ".tasia", "rules.yaml"), []byte(`rules:
  - id: custom_nopattern
    severity: HIGH
`), 0o644)

	err := Run([]string{"lint", "--path", dir})
	if err == nil {
		t.Fatal("lint should fail on missing pattern")
	}
}

func TestLintCustomRulesBadPrefix(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".tasia"), 0o755)
	os.WriteFile(filepath.Join(dir, ".tasia", "rules.yaml"), []byte(`rules:
  - id: bad_prefix
    pattern: "test"
    severity: HIGH
`), 0o644)

	err := Run([]string{"lint", "--path", dir})
	if err == nil {
		t.Fatal("lint should fail on bad ID prefix")
	}
}

func TestLintNoConfigFiles(t *testing.T) {
	dir := t.TempDir()
	err := Run([]string{"lint", "--path", dir})
	if err != nil {
		t.Fatalf("lint should pass on empty dir: %v", err)
	}
}

func TestLintJSON(t *testing.T) {
	dir := t.TempDir()
	err := Run([]string{"lint", "--path", dir, "--format", "json"})
	if err != nil {
		t.Fatalf("lint json: %v", err)
	}
}
