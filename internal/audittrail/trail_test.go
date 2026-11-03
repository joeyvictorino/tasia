package audittrail

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestNewEntry(t *testing.T) {
	findings := []rules.Finding{
		{ID: "r1", Severity: "HIGH", File: "a.yml", Line: 1},
		{ID: "r2", Severity: "HIGH", File: "b.yml", Line: 2},
		{ID: "r3", Severity: "LOW", File: "c.yml", Line: 3},
	}
	e := NewEntry("/tmp/test", "1.0.0", findings)
	if e.FindingCount != 3 {
		t.Errorf("finding count = %d, want 3", e.FindingCount)
	}
	if e.BySeverity["HIGH"] != 2 {
		t.Errorf("HIGH count = %d, want 2", e.BySeverity["HIGH"])
	}
	if e.BySeverity["LOW"] != 1 {
		t.Errorf("LOW count = %d, want 1", e.BySeverity["LOW"])
	}
	if e.Checksum == "" {
		t.Error("checksum should not be empty")
	}
	if e.Version != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", e.Version)
	}
}

func TestNewEntryEmpty(t *testing.T) {
	e := NewEntry("/tmp", "dev", nil)
	if e.FindingCount != 0 {
		t.Errorf("finding count = %d, want 0", e.FindingCount)
	}
}

func TestAppendAndLoad(t *testing.T) {
	dir := t.TempDir()
	trailPath := filepath.Join(dir, "trail.json")

	e1 := NewEntry("/a", "1.0", []rules.Finding{{ID: "x", Severity: "HIGH", File: "f", Line: 1}})
	if err := AppendEntry(trailPath, e1); err != nil {
		t.Fatal(err)
	}

	e2 := NewEntry("/b", "1.1", nil)
	if err := AppendEntry(trailPath, e2); err != nil {
		t.Fatal(err)
	}

	trail, err := LoadTrail(trailPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(trail.Entries) != 2 {
		t.Errorf("entries = %d, want 2", len(trail.Entries))
	}
	if trail.Entries[0].ScanPath != "/a" {
		t.Errorf("first entry path = %q, want /a", trail.Entries[0].ScanPath)
	}
}

func TestLatestEntry(t *testing.T) {
	dir := t.TempDir()
	trailPath := filepath.Join(dir, "trail.json")

	AppendEntry(trailPath, NewEntry("/first", "1.0", nil))
	AppendEntry(trailPath, NewEntry("/second", "1.1", nil))

	latest, err := LatestEntry(trailPath)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ScanPath != "/second" {
		t.Errorf("latest path = %q, want /second", latest.ScanPath)
	}
}

func TestLatestEntryEmptyTrail(t *testing.T) {
	dir := t.TempDir()
	trailPath := filepath.Join(dir, "trail.json")
	os.WriteFile(trailPath, []byte(`{"entries":[]}`), 0644)

	_, err := LatestEntry(trailPath)
	if err == nil {
		t.Error("expected error for empty trail")
	}
}

func TestLoadTrailNotFound(t *testing.T) {
	_, err := LoadTrail("/nonexistent/trail.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestChecksumConsistency(t *testing.T) {
	findings := []rules.Finding{{ID: "r1", Severity: "HIGH", File: "a.yml", Line: 1}}
	e1 := NewEntry("/tmp", "1.0", findings)
	e2 := NewEntry("/tmp", "1.0", findings)
	if e1.Checksum != e2.Checksum {
		t.Errorf("same findings should produce same checksum: %s vs %s", e1.Checksum, e2.Checksum)
	}
}

func TestFormatText(t *testing.T) {
	trail := AuditTrail{
		Entries: []AuditEntry{
			{Timestamp: "2024-01-01T00:00:00Z", ScanPath: "/app", FindingCount: 5, Checksum: "abc123", Version: "1.0"},
		},
	}
	txt := FormatText(trail)
	if txt == "" {
		t.Error("format text should not be empty")
	}
}

func TestJSONRoundtrip(t *testing.T) {
	e := NewEntry("/tmp", "1.0", []rules.Finding{{ID: "r1", Severity: "HIGH", File: "f", Line: 1}})
	trail := AuditTrail{Entries: []AuditEntry{e}}
	data, _ := json.Marshal(trail)
	var trail2 AuditTrail
	if err := json.Unmarshal(data, &trail2); err != nil {
		t.Fatal(err)
	}
	if len(trail2.Entries) != 1 {
		t.Errorf("entries = %d, want 1", len(trail2.Entries))
	}
}
