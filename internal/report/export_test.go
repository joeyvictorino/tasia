package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func testFindings() []rules.Finding {
	return []rules.Finding{
		{ID: "exposed_inference", Severity: rules.SeverityHigh, Title: "Inference API published", File: "docker-compose.yml", Line: 10, Evidence: "ports: 11434:11434", Why: "Exposes model API", Fix: "Bind to 127.0.0.1"},
		{ID: "privileged_container", Severity: rules.SeverityCritical, Title: "Privileged container", File: "docker-compose.yml", Line: 20, Evidence: "privileged: true", Why: "Full host access", Fix: "Remove privileged"},
		{ID: "latest_image", Severity: rules.SeverityMedium, Title: "Mutable image tag", File: "docker-compose.yml", Line: 5, Evidence: "image: ollama:latest", Why: "Non-reproducible", Fix: "Pin to specific tag"},
	}
}

func TestExportCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := ExportCSV(testFindings(), &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "severity,rule_id,title,file,line,evidence") {
		t.Error("missing CSV header")
	}
	if !strings.Contains(out, "exposed_inference") {
		t.Error("missing exposed_inference row")
	}
	if !strings.Contains(out, "privileged_container") {
		t.Error("missing privileged_container row")
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 { // header + 3 findings
		t.Errorf("expected 4 lines, got %d", len(lines))
	}
}

func TestExportCSVEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := ExportCSV(nil, &buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Errorf("empty findings should produce header only, got %d lines", len(lines))
	}
}

func TestExportMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := ExportMarkdown(testFindings(), &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "# Tasia Security Findings") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "## CRITICAL (1)") {
		t.Error("missing CRITICAL section")
	}
	if !strings.Contains(out, "## HIGH (1)") {
		t.Error("missing HIGH section")
	}
	if !strings.Contains(out, "## MEDIUM (1)") {
		t.Error("missing MEDIUM section")
	}
	if !strings.Contains(out, "exposed_inference") {
		t.Error("missing finding in markdown")
	}
}

func TestExportMarkdownEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := ExportMarkdown(nil, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No findings.") {
		t.Error("empty findings should say 'No findings.'")
	}
}

func TestExportJUnit(t *testing.T) {
	var buf bytes.Buffer
	if err := ExportJUnit(testFindings(), &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "<?xml") {
		t.Error("missing XML header")
	}
	if !strings.Contains(out, "<testsuites>") {
		t.Error("missing testsuites element")
	}
	if !strings.Contains(out, `name="tasia"`) {
		t.Error("missing suite name")
	}
	if !strings.Contains(out, `tests="3"`) {
		t.Error("expected tests=3")
	}
	if !strings.Contains(out, `failures="3"`) {
		t.Error("expected failures=3")
	}
	if !strings.Contains(out, "exposed_inference") {
		t.Error("missing finding in JUnit")
	}
	if !strings.Contains(out, `type="CRITICAL"`) {
		t.Error("missing CRITICAL severity type")
	}
}

func TestExportJUnitEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := ExportJUnit(nil, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `tests="0"`) {
		t.Error("empty findings should have tests=0")
	}
}

func TestExportMarkdownEscapesPipes(t *testing.T) {
	findings := []rules.Finding{
		{ID: "test_rule", Severity: rules.SeverityHigh, Title: "Title | with pipe", File: "file.yml", Line: 1, Evidence: "ev | pipe"},
	}
	var buf bytes.Buffer
	if err := ExportMarkdown(findings, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "Title | with") {
		t.Error("pipes should be escaped in markdown tables")
	}
	if !strings.Contains(out, `Title \| with pipe`) {
		t.Error("expected escaped pipe in title")
	}
}
