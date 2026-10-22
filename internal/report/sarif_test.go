package report

import (
	"encoding/json"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestFindingsToSARIF(t *testing.T) {
	findings := []rules.Finding{
		{
			ID:       "exposed_inference",
			Severity: rules.SeverityHigh,
			Title:    "Inference API published to all interfaces",
			File:     `configs/docker-compose.yml`,
			Line:     5,
			Why:      "The API may be reachable by unintended systems.",
			Fix:      "Bind it to localhost.",
		},
		{
			ID:       "no_ai_stack_manifest",
			Severity: rules.SeverityLow,
			Title:    "No AI stack manifest",
			File:     "ai-stack-manifest.json",
			Fix:      "Document the stack.",
		},
	}

	out, err := FindingsToSARIF(findings, "BLOCKED", "HIGH")
	if err != nil {
		t.Fatalf("FindingsToSARIF: %v", err)
	}
	var parsed sarifLog
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if parsed.Schema != sarifSchema || parsed.Version != "2.1.0" || len(parsed.Runs) != 1 {
		t.Fatalf("unexpected SARIF envelope: %+v", parsed)
	}
	run := parsed.Runs[0]
	if run.Tool.Driver.Name != "Tasia" || len(run.Tool.Driver.Rules) != 2 || len(run.Results) != 2 {
		t.Fatalf("unexpected SARIF run: %+v", run)
	}
	if run.Results[0].Level != "error" || run.Results[0].Locations[0].PhysicalLocation.Region.StartLine != 5 {
		t.Errorf("high finding mapping is wrong: %+v", run.Results[0])
	}
	if run.Results[1].Level != "note" || run.Results[1].Locations[0].PhysicalLocation.Region != nil {
		t.Errorf("low finding mapping is wrong: %+v", run.Results[1])
	}
	if run.Properties["decision"] != "BLOCKED" || run.Properties["risk"] != "HIGH" {
		t.Errorf("decision metadata missing: %+v", run.Properties)
	}
}

func TestErrorSARIFIsFailClosed(t *testing.T) {
	out := ErrorSARIF([]collect.ConfigError{{Path: `stack/docker-compose.yml`, Err: "yaml parse failed"}})
	var parsed sarifLog
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	run := parsed.Runs[0]
	if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("parse failure must be executionSuccessful=false: %+v", run.Invocations)
	}
	if len(run.Invocations[0].ToolExecutionNotifications) != 1 {
		t.Fatalf("parse failure notification missing: %+v", run.Invocations[0])
	}
	if run.Properties["decision"] != "ERROR" || run.Properties["risk"] != "UNKNOWN" {
		t.Errorf("fail-closed metadata missing: %+v", run.Properties)
	}
}

func TestSARIFSeverityLevels(t *testing.T) {
	tests := map[rules.Severity]string{
		rules.SeverityCritical: "error",
		rules.SeverityHigh:     "error",
		rules.SeverityMedium:   "warning",
		rules.SeverityLow:      "note",
	}
	for severity, want := range tests {
		if got := sarifLevel(severity); got != want {
			t.Errorf("sarifLevel(%q) = %q, want %q", severity, got, want)
		}
	}
}
