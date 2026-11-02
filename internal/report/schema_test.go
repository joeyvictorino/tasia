package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestSchemaVersionSemver(t *testing.T) {
	parts := strings.Split(SchemaVersion, ".")
	if len(parts) != 3 {
		t.Fatalf("SchemaVersion %q is not semver (want MAJOR.MINOR.PATCH)", SchemaVersion)
	}
}

func TestFindingsJSONSchemaIsValidJSON(t *testing.T) {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(FindingsJSONSchema), &m); err != nil {
		t.Fatalf("FindingsJSONSchema is not valid JSON: %v", err)
	}
	if m["title"] == nil {
		t.Error("schema should have a title")
	}
	defs, ok := m["$defs"].(map[string]interface{})
	if !ok {
		t.Fatal("schema should have $defs")
	}
	for _, def := range []string{"finding", "parse_error", "scan_summary"} {
		if defs[def] == nil {
			t.Errorf("schema should define %q", def)
		}
	}
}

func TestFindingsToJSONIncludesSchemaVersion(t *testing.T) {
	findings := []rules.Finding{{
		ID: "test_rule", Severity: rules.SeverityHigh,
		Title: "test", File: "f.yaml", Line: 1,
		Evidence: "x=1", Why: "because", Fix: "fix it",
	}}
	out, err := FindingsToJSON(findings, "BLOCKED", "HIGH", nil)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal(err)
	}
	sv, ok := parsed["schema_version"].(string)
	if !ok || sv == "" {
		t.Error("JSON output should include schema_version")
	}
	if sv != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", sv, SchemaVersion)
	}
}

func TestErrorJSONIncludesSchemaVersion(t *testing.T) {
	errs := []collect.ConfigError{{Path: "bad.yaml", Err: "parse failed"}}
	out := ErrorJSON(errs)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal(err)
	}
	sv, ok := parsed["schema_version"].(string)
	if !ok || sv == "" {
		t.Error("ErrorJSON should include schema_version")
	}
}
