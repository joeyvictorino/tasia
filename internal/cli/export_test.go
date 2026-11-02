package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportCSVCLI(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "findings.csv")

	// Export from an empty dir (no compose files = no findings)
	err := Run([]string{"export", "--path", dir, "--format", "csv", "--output", outFile})
	if err != nil {
		t.Fatalf("export csv: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "severity,rule_id") {
		t.Error("CSV output should contain header")
	}
}

func TestExportMarkdownCLI(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "findings.md")

	err := Run([]string{"export", "--path", dir, "--format", "markdown", "--output", outFile})
	if err != nil {
		t.Fatalf("export markdown: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "# Tasia Security Findings") {
		t.Error("Markdown output should contain header")
	}
}

func TestExportJUnitCLI(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "findings.xml")

	err := Run([]string{"export", "--path", dir, "--format", "junit", "--output", outFile})
	if err != nil {
		t.Fatalf("export junit: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "<testsuites>") {
		t.Error("JUnit output should contain testsuites element")
	}
}

func TestExportUnknownFormat(t *testing.T) {
	dir := t.TempDir()
	err := Run([]string{"export", "--path", dir, "--format", "xyz"})
	if err == nil {
		t.Error("expected error for unknown format")
	}
}
