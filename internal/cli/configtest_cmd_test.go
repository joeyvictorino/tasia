package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateConfigEmpty(t *testing.T) {
	dir := t.TempDir()
	r := validateConfig(dir)
	if !r.Valid {
		t.Error("empty config should be valid")
	}
	if r.RulesOverridden != 0 {
		t.Errorf("expected 0 overrides, got %d", r.RulesOverridden)
	}
}

func TestValidateConfigValidOverrides(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".tasiarc.yaml"), []byte(`
severities:
  privileged_container: CRITICAL
  latest_image: LOW
`), 0644)
	r := validateConfig(dir)
	if !r.Valid {
		t.Errorf("valid overrides should pass: %+v", r.Errors)
	}
	if r.RulesOverridden != 2 {
		t.Errorf("expected 2 overrides, got %d", r.RulesOverridden)
	}
}

func TestValidateConfigUnknownRule(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".tasiarc.yaml"), []byte(`
severities:
  nonexistent_rule: HIGH
`), 0644)
	r := validateConfig(dir)
	if r.Valid {
		t.Error("unknown rule should cause failure")
	}
	found := false
	for _, e := range r.Errors {
		if strings.Contains(e.Message, "unknown rule") {
			found = true
		}
	}
	if !found {
		t.Error("expected 'unknown rule' error")
	}
}

func TestValidateConfigInvalidSeverity(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".tasiarc.yaml"), []byte(`
severities:
  privileged_container: EXTREME
`), 0644)
	r := validateConfig(dir)
	if r.Valid {
		t.Error("invalid severity should cause failure")
	}
	found := false
	for _, e := range r.Errors {
		if strings.Contains(e.Message, "invalid severity") {
			found = true
		}
	}
	if !found {
		t.Error("expected 'invalid severity' error")
	}
}

func TestValidateConfigBadYAML(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".tasiarc.yaml"), []byte(`{{{bad yaml`), 0644)
	r := validateConfig(dir)
	if r.Valid {
		t.Error("bad YAML should cause failure")
	}
}

func TestFormatConfigTestTextPass(t *testing.T) {
	r := configTestResult{ConfigPath: ".", Valid: true, RulesOverridden: 2}
	text := formatConfigTestText(r)
	if !strings.Contains(text, "PASS") {
		t.Error("expected PASS in output")
	}
}

func TestFormatConfigTestTextFail(t *testing.T) {
	r := configTestResult{
		ConfigPath: ".",
		Valid:      false,
		Errors:     []configTestError{{Field: "test", Message: "bad"}},
	}
	text := formatConfigTestText(r)
	if !strings.Contains(text, "FAIL") {
		t.Error("expected FAIL in output")
	}
	if !strings.Contains(text, "bad") {
		t.Error("expected error message")
	}
}

func TestKnownRuleIDs(t *testing.T) {
	if !knownRuleIDs["privileged_container"] {
		t.Error("privileged_container should be known")
	}
	if knownRuleIDs["totally_fake"] {
		t.Error("totally_fake should not be known")
	}
}
