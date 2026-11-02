package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestBaselineCreate(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`services:
  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
`), 0o644)

	outFile := filepath.Join(dir, "baseline.json")
	err := Run([]string{"baseline", "create", "--path", dir, "--output", outFile})
	if err != nil {
		t.Fatalf("baseline create: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading baseline: %v", err)
	}
	var snap BaselineSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("parsing baseline: %v", err)
	}
	if len(snap.Findings) == 0 {
		t.Error("expected findings in baseline")
	}
	if snap.Version == "" {
		t.Error("expected version in baseline")
	}
	if snap.Timestamp == "" {
		t.Error("expected timestamp in baseline")
	}
	if len(snap.FindingHashes) != len(snap.Findings) {
		t.Error("finding hashes count should match findings count")
	}
}

func TestBaselineCompareFindsNewAndResolved(t *testing.T) {
	baseFinding := rules.Finding{
		ID:       "exposed_inference",
		Severity: "HIGH",
		File:     "docker-compose.yml",
		Line:     5,
	}
	currentFinding := rules.Finding{
		ID:       "privileged_container",
		Severity: "CRITICAL",
		File:     "docker-compose.yml",
		Line:     10,
	}

	baseSummaries := findingsToSummaries([]rules.Finding{baseFinding})
	snap := BaselineSnapshot{
		Version:       "test",
		Timestamp:     "2026-01-01T00:00:00Z",
		Path:          "/test",
		FindingHashes: []string{baseSummaries[0].Hash},
		Findings:      baseSummaries,
	}

	comp := compareBaseline(snap, []rules.Finding{currentFinding})

	if len(comp.New) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(comp.New))
	}
	if len(comp.Resolved) != 1 {
		t.Errorf("expected 1 resolved finding, got %d", len(comp.Resolved))
	}
	if len(comp.Unchanged) != 0 {
		t.Errorf("expected 0 unchanged, got %d", len(comp.Unchanged))
	}
}

func TestBaselineUpdate(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	os.WriteFile(compose, []byte(`services:
  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
`), 0o644)

	outFile := filepath.Join(dir, "baseline.json")
	if err := Run([]string{"baseline", "create", "--path", dir, "--output", outFile}); err != nil {
		t.Fatalf("create: %v", err)
	}

	data1, _ := os.ReadFile(outFile)
	var snap1 BaselineSnapshot
	json.Unmarshal(data1, &snap1)

	if err := Run([]string{"baseline", "update", "--baseline", outFile, "--path", dir}); err != nil {
		t.Fatalf("update: %v", err)
	}

	data2, _ := os.ReadFile(outFile)
	var snap2 BaselineSnapshot
	json.Unmarshal(data2, &snap2)

	if len(snap1.Findings) != len(snap2.Findings) {
		t.Error("update should produce same findings count for unchanged project")
	}
}

func TestBaselineEmptyScan(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "baseline.json")

	if err := Run([]string{"baseline", "create", "--path", dir, "--output", outFile}); err != nil {
		t.Fatalf("create: %v", err)
	}

	data, _ := os.ReadFile(outFile)
	var snap BaselineSnapshot
	json.Unmarshal(data, &snap)

	if len(snap.Findings) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %d", len(snap.Findings))
	}
}

func TestHashFindingDeterministic(t *testing.T) {
	f := rules.Finding{
		ID:       "test_rule",
		Severity: "HIGH",
		File:     "test.yml",
		Line:     42,
	}
	h1 := hashFinding(f)
	h2 := hashFinding(f)
	if h1 != h2 {
		t.Error("hash should be deterministic")
	}
	if h1 == "" {
		t.Error("hash should not be empty")
	}
}
