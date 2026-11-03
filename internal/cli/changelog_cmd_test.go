package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildChangelogEmpty(t *testing.T) {
	result := buildChangelog(nil)
	if result.TotalEntries != 0 {
		t.Errorf("expected 0 entries, got %d", result.TotalEntries)
	}
}

func TestBuildChangelogSingle(t *testing.T) {
	entries := []changelogEntry{
		{Timestamp: "2025-01-01T00:00:00Z", Version: "1.0", FindingCount: 3, Findings: []string{"f1", "f2", "f3"}},
	}
	result := buildChangelog(entries)
	if result.TotalEntries != 1 {
		t.Errorf("expected 1 entry, got %d", result.TotalEntries)
	}
	if result.Changes[0].Delta != 3 {
		t.Errorf("expected delta 3, got %d", result.Changes[0].Delta)
	}
}

func TestBuildChangelogDelta(t *testing.T) {
	entries := []changelogEntry{
		{Timestamp: "2025-01-01T00:00:00Z", Version: "1.0", FindingCount: 3, Findings: []string{"f1", "f2", "f3"}},
		{Timestamp: "2025-01-02T00:00:00Z", Version: "1.1", FindingCount: 2, Findings: []string{"f1", "f3"}},
	}
	result := buildChangelog(entries)
	if result.NetDelta != -1 {
		t.Errorf("expected net delta -1, got %d", result.NetDelta)
	}
	second := result.Changes[1]
	if len(second.Resolved) != 1 || second.Resolved[0] != "f2" {
		t.Errorf("expected resolved f2, got %v", second.Resolved)
	}
}

func TestBuildChangelogIntroduced(t *testing.T) {
	entries := []changelogEntry{
		{Timestamp: "2025-01-01T00:00:00Z", Version: "1.0", FindingCount: 1, Findings: []string{"f1"}},
		{Timestamp: "2025-01-02T00:00:00Z", Version: "1.1", FindingCount: 2, Findings: []string{"f1", "f2"}},
	}
	result := buildChangelog(entries)
	second := result.Changes[1]
	if len(second.Introduced) != 1 || second.Introduced[0] != "f2" {
		t.Errorf("expected introduced f2, got %v", second.Introduced)
	}
}

func TestRunChangelogTextOutput(t *testing.T) {
	entries := []changelogEntry{
		{Timestamp: "2025-01-01T00:00:00Z", Version: "1.0", FindingCount: 2, Findings: []string{"a", "b"}},
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "trail.json")
	data, _ := json.Marshal(entries)
	os.WriteFile(f, data, 0644)

	result := buildChangelog(entries)
	text := formatChangelogText(result)
	if !strings.Contains(text, "Security Changelog") {
		t.Errorf("missing header: %s", text)
	}
	if !strings.Contains(text, "v1.0") {
		t.Errorf("missing version: %s", text)
	}
}
