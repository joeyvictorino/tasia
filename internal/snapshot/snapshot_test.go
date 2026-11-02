package snapshot

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestCreateSnapshotEmpty(t *testing.T) {
	s := CreateSnapshot("/tmp/test", "1.0.0", nil)
	if s.FindingCount != 0 {
		t.Errorf("finding count = %d, want 0", s.FindingCount)
	}
	if s.Version != "1.0.0" {
		t.Errorf("version = %s, want 1.0.0", s.Version)
	}
	if s.Checksum == "" {
		t.Error("checksum should not be empty")
	}
}

func TestCreateSnapshotWithFindings(t *testing.T) {
	findings := []rules.Finding{
		{ID: "rule1", Severity: rules.SeverityHigh, File: "docker-compose.yml", Title: "test finding 1"},
		{ID: "rule2", Severity: rules.SeverityLow, File: "Dockerfile", Title: "test finding 2"},
	}
	s := CreateSnapshot("/tmp/test", "1.0.0", findings)
	if s.FindingCount != 2 {
		t.Errorf("finding count = %d, want 2", s.FindingCount)
	}
	if s.BySeverity["HIGH"] != 1 {
		t.Errorf("HIGH count = %d, want 1", s.BySeverity["HIGH"])
	}
	if s.BySeverity["LOW"] != 1 {
		t.Errorf("LOW count = %d, want 1", s.BySeverity["LOW"])
	}
	for _, f := range s.Findings {
		if f.Hash == "" {
			t.Error("finding hash should not be empty")
		}
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "snapshot.json")

	findings := []rules.Finding{
		{ID: "rule1", Severity: rules.SeverityHigh, File: "compose.yml", Title: "no auth"},
	}
	original := CreateSnapshot("/tmp/test", "1.0.0", findings)
	if err := SaveSnapshot(original, outPath); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSnapshot(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Checksum != original.Checksum {
		t.Errorf("checksum mismatch: %s != %s", loaded.Checksum, original.Checksum)
	}
	if loaded.FindingCount != original.FindingCount {
		t.Errorf("finding count mismatch: %d != %d", loaded.FindingCount, original.FindingCount)
	}
	if len(loaded.Findings) != len(original.Findings) {
		t.Errorf("findings length mismatch: %d != %d", len(loaded.Findings), len(original.Findings))
	}
}

func TestLoadSnapshotNotFound(t *testing.T) {
	_, err := LoadSnapshot("/nonexistent/path/snapshot.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestChecksumConsistency(t *testing.T) {
	findings := []rules.Finding{
		{ID: "rule1", Severity: rules.SeverityHigh, File: "compose.yml", Title: "finding A"},
		{ID: "rule2", Severity: rules.SeverityLow, File: "Dockerfile", Title: "finding B"},
	}
	s1 := CreateSnapshot("/tmp/test", "1.0.0", findings)
	s2 := CreateSnapshot("/tmp/test", "1.0.0", findings)
	if s1.Checksum != s2.Checksum {
		t.Errorf("same findings should produce same checksum: %s != %s", s1.Checksum, s2.Checksum)
	}
}

func TestSaveCreatesFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.json")
	s := CreateSnapshot("/tmp", "dev", nil)
	if err := SaveSnapshot(s, outPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("file should exist: %v", err)
	}
}
