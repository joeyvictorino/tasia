package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestLoadCustomRules(t *testing.T) {
	dir := t.TempDir()
	yaml := `rules:
  - id: custom_no_debug
    severity: HIGH
    category: security
    pattern: "DEBUG\\s*=\\s*true"
    file_pattern: "*.yaml"
    message: Debug mode enabled
    description: Debug mode should not be enabled in production
  - id: custom_api_key
    severity: CRITICAL
    pattern: "api_key:\\s*\\S+"
    message: Hardcoded API key detected
`
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadCustomRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].ID != "custom_no_debug" {
		t.Errorf("rule 0 ID = %q", rules[0].ID)
	}
	if rules[1].Severity != SeverityCritical {
		t.Errorf("rule 1 severity = %q, want CRITICAL", rules[1].Severity)
	}
}

func TestLoadCustomRulesInvalidID(t *testing.T) {
	dir := t.TempDir()
	yaml := `rules:
  - id: bad_id
    pattern: "x"
    message: test
`
	path := filepath.Join(dir, "rules.yaml")
	os.WriteFile(path, []byte(yaml), 0o644)

	_, err := LoadCustomRules(path)
	if err == nil {
		t.Fatal("expected error for invalid rule ID")
	}
}

func TestLoadCustomRulesInvalidPattern(t *testing.T) {
	dir := t.TempDir()
	yaml := `rules:
  - id: custom_bad
    pattern: "["
    message: test
`
	path := filepath.Join(dir, "rules.yaml")
	os.WriteFile(path, []byte(yaml), 0o644)

	_, err := LoadCustomRules(path)
	if err == nil {
		t.Fatal("expected error for invalid regex pattern")
	}
}

func TestMatchCustomRules(t *testing.T) {
	rules := []CustomRule{
		{
			ID:       "custom_debug",
			Severity: SeverityHigh,
			Pattern:  "DEBUG\\s*=\\s*true",
			Message:  "Debug enabled",
		},
	}
	for i := range rules {
		rules[i].compiled = mustCompile(rules[i].Pattern)
	}

	content := []byte("line1\nDEBUG = true\nline3")
	findings := MatchCustomRules(rules, "config.yaml", content)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Line != 2 {
		t.Errorf("line = %d, want 2", findings[0].Line)
	}
	if findings[0].ID != "custom_debug" {
		t.Errorf("id = %q", findings[0].ID)
	}
}

func TestMatchCustomRulesFilePattern(t *testing.T) {
	rules := []CustomRule{
		{
			ID:          "custom_yml",
			Severity:    SeverityLow,
			Pattern:     "test",
			FilePattern: "*.yaml",
			Message:     "found test",
		},
	}
	for i := range rules {
		rules[i].compiled = mustCompile(rules[i].Pattern)
	}

	findings := MatchCustomRules(rules, "config.json", []byte("test"))
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-matching file pattern, got %d", len(findings))
	}

	findings = MatchCustomRules(rules, "config.yaml", []byte("test"))
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for matching file pattern, got %d", len(findings))
	}
}

func TestFindCustomRulesFile(t *testing.T) {
	dir := t.TempDir()

	p := FindCustomRulesFile(dir)
	if p != "" {
		t.Errorf("expected empty for missing file, got %q", p)
	}

	tasiaDir := filepath.Join(dir, ".tasia")
	os.MkdirAll(tasiaDir, 0o755)
	os.WriteFile(filepath.Join(tasiaDir, "rules.yaml"), []byte("rules: []"), 0o644)

	p = FindCustomRulesFile(dir)
	if p == "" {
		t.Error("expected non-empty path for existing file")
	}
}

func mustCompile(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
