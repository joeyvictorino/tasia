package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeTestScan(t *testing.T, dir, name, decision string, findings []metricsF) {
	t.Helper()
	scan := metricsJSON{
		Decision: decision,
		Risk:     "LOW",
		Summary:  &metricsSummary{TotalFindings: len(findings), BySeverity: map[string]int{}},
		Findings: findings,
	}
	data, _ := json.MarshalIndent(scan, "", "  ")
	os.WriteFile(filepath.Join(dir, name), data, 0644)
}

func TestMetricsBasic(t *testing.T) {
	dir := t.TempDir()
	writeTestScan(t, dir, "run1.json", "PASS", []metricsF{
		{ID: "exposed_port", Severity: "HIGH", Title: "Exposed port"},
	})
	writeTestScan(t, dir, "run2.json", "PASS", nil)

	err := runMetrics([]string{"--dir", dir, "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMetricsText(t *testing.T) {
	dir := t.TempDir()
	writeTestScan(t, dir, "scan.json", "BLOCKED", []metricsF{
		{ID: "docker_socket", Severity: "CRITICAL"},
		{ID: "exposed_port", Severity: "HIGH"},
	})

	err := runMetrics([]string{"--dir", dir})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMetricsMissingDir(t *testing.T) {
	err := runMetrics(nil)
	if err == nil {
		t.Fatal("expected error for missing --dir")
	}
}

func TestMetricsEmptyDir(t *testing.T) {
	dir := t.TempDir()
	err := runMetrics([]string{"--dir", dir})
	if err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestMetricsPassRate(t *testing.T) {
	dir := t.TempDir()
	writeTestScan(t, dir, "a.json", "PASS", nil)
	writeTestScan(t, dir, "b.json", "BLOCKED", []metricsF{{ID: "x", Severity: "HIGH"}})
	writeTestScan(t, dir, "c.json", "PASS", nil)

	err := runMetrics([]string{"--dir", dir, "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMetricsSkipsBadFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte("not json"), 0644)
	writeTestScan(t, dir, "good.json", "PASS", nil)

	err := runMetrics([]string{"--dir", dir})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFormatSevBreakdown(t *testing.T) {
	m := map[string]int{"CRITICAL": 1, "HIGH": 3, "LOW": 2}
	got := formatSevBreakdown(m)
	if got == "" {
		t.Fatal("expected non-empty breakdown")
	}
}
