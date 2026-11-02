package cli

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestSeverityCountsCorrect(t *testing.T) {
	findings := []rules.Finding{
		{ID: "r1", Severity: "CRITICAL"},
		{ID: "r2", Severity: "HIGH"},
		{ID: "r3", Severity: "HIGH"},
		{ID: "r4", Severity: "MEDIUM"},
		{ID: "r5", Severity: "LOW"},
	}
	report := buildSeverityReport(findings, "")

	if report.Counts["CRITICAL"] != 1 {
		t.Errorf("CRITICAL: got %d, want 1", report.Counts["CRITICAL"])
	}
	if report.Counts["HIGH"] != 2 {
		t.Errorf("HIGH: got %d, want 2", report.Counts["HIGH"])
	}
	if report.Counts["MEDIUM"] != 1 {
		t.Errorf("MEDIUM: got %d, want 1", report.Counts["MEDIUM"])
	}
	if report.Counts["LOW"] != 1 {
		t.Errorf("LOW: got %d, want 1", report.Counts["LOW"])
	}
	if report.TotalFindings != 5 {
		t.Errorf("total: got %d, want 5", report.TotalFindings)
	}
}

func TestSeverityPercentagesSum(t *testing.T) {
	findings := []rules.Finding{
		{ID: "r1", Severity: "CRITICAL"},
		{ID: "r2", Severity: "HIGH"},
		{ID: "r3", Severity: "MEDIUM"},
		{ID: "r4", Severity: "LOW"},
	}
	report := buildSeverityReport(findings, "")

	total := 0.0
	for _, pct := range report.Percentages {
		total += pct
	}
	if math.Abs(total-100.0) > 0.1 {
		t.Errorf("percentages sum to %.1f, want 100.0", total)
	}
}

func TestSeverityRiskScore(t *testing.T) {
	findings := []rules.Finding{
		{ID: "r1", Severity: "CRITICAL"},
		{ID: "r2", Severity: "HIGH"},
		{ID: "r3", Severity: "MEDIUM"},
		{ID: "r4", Severity: "LOW"},
	}
	report := buildSeverityReport(findings, "")

	expected := 10 + 5 + 2 + 1
	if report.RiskScore != expected {
		t.Errorf("risk score: got %d, want %d", report.RiskScore, expected)
	}
}

func TestSeverityTrendImproving(t *testing.T) {
	dir := t.TempDir()
	baselineFile := filepath.Join(dir, "baseline.json")

	snap := BaselineSnapshot{
		Version:   "test",
		Timestamp: "2026-01-01T00:00:00Z",
		Findings: []FindingSummary{
			{Severity: "CRITICAL"},
			{Severity: "HIGH"},
			{Severity: "HIGH"},
		},
	}
	data, _ := json.Marshal(snap)
	os.WriteFile(baselineFile, data, 0o644)

	currentFindings := []rules.Finding{
		{ID: "r1", Severity: "LOW"},
	}
	report := buildSeverityReport(currentFindings, baselineFile)

	if report.Trend != "improving" {
		t.Errorf("trend: got %q, want %q", report.Trend, "improving")
	}
}

func TestSeverityTrendDegrading(t *testing.T) {
	dir := t.TempDir()
	baselineFile := filepath.Join(dir, "baseline.json")

	snap := BaselineSnapshot{
		Version:   "test",
		Timestamp: "2026-01-01T00:00:00Z",
		Findings: []FindingSummary{
			{Severity: "LOW"},
		},
	}
	data, _ := json.Marshal(snap)
	os.WriteFile(baselineFile, data, 0o644)

	currentFindings := []rules.Finding{
		{ID: "r1", Severity: "CRITICAL"},
		{ID: "r2", Severity: "HIGH"},
	}
	report := buildSeverityReport(currentFindings, baselineFile)

	if report.Trend != "degrading" {
		t.Errorf("trend: got %q, want %q", report.Trend, "degrading")
	}
}

func TestSeverityTrendStable(t *testing.T) {
	dir := t.TempDir()
	baselineFile := filepath.Join(dir, "baseline.json")

	snap := BaselineSnapshot{
		Version:   "test",
		Timestamp: "2026-01-01T00:00:00Z",
		Findings: []FindingSummary{
			{Severity: "HIGH"},
		},
	}
	data, _ := json.Marshal(snap)
	os.WriteFile(baselineFile, data, 0o644)

	currentFindings := []rules.Finding{
		{ID: "r1", Severity: "HIGH"},
	}
	report := buildSeverityReport(currentFindings, baselineFile)

	if report.Trend != "stable" {
		t.Errorf("trend: got %q, want %q", report.Trend, "stable")
	}
}

func TestSeverityEmptyFindings(t *testing.T) {
	report := buildSeverityReport(nil, "")

	if report.TotalFindings != 0 {
		t.Errorf("total: got %d, want 0", report.TotalFindings)
	}
	if report.RiskScore != 0 {
		t.Errorf("risk score: got %d, want 0", report.RiskScore)
	}
	if report.Trend != "" {
		t.Errorf("trend should be empty without baseline, got %q", report.Trend)
	}
}

func TestSeverityCLIJSON(t *testing.T) {
	dir := t.TempDir()
	err := Run([]string{"severity", "--path", dir, "--format", "json"})
	if err != nil {
		t.Fatalf("severity: %v", err)
	}
}
