package changelog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/snapshot"
)

func writeSnapshot(t *testing.T, dir, name string, s snapshot.Snapshot) string {
	t.Helper()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGenerateChangelogNoChanges(t *testing.T) {
	dir := t.TempDir()
	findings := []snapshot.SnapshotFinding{
		{RuleID: "exposed_inference", Severity: "HIGH", File: "docker-compose.yml", Message: "port open", Hash: "aaa111"},
	}
	base := snapshot.Snapshot{Checksum: "abc123def456", Findings: findings}
	current := snapshot.Snapshot{Checksum: "abc123def456", Findings: findings}

	bp := writeSnapshot(t, dir, "base.json", base)
	cp := writeSnapshot(t, dir, "current.json", current)

	cl, err := GenerateChangelog(bp, cp)
	if err != nil {
		t.Fatal(err)
	}
	if len(cl.NewFindings) != 0 {
		t.Errorf("expected 0 new findings, got %d", len(cl.NewFindings))
	}
	if len(cl.Resolved) != 0 {
		t.Errorf("expected 0 resolved, got %d", len(cl.Resolved))
	}
	if cl.Summary != "No changes detected." {
		t.Errorf("unexpected summary: %s", cl.Summary)
	}
}

func TestGenerateChangelogNewAndResolved(t *testing.T) {
	dir := t.TempDir()
	base := snapshot.Snapshot{
		Checksum: "base000000000",
		Findings: []snapshot.SnapshotFinding{
			{RuleID: "exposed_inference", Severity: "HIGH", File: "compose.yml", Message: "port open", Hash: "hash_a"},
			{RuleID: "latest_image", Severity: "MEDIUM", File: "compose.yml", Message: "uses latest", Hash: "hash_b"},
		},
	}
	current := snapshot.Snapshot{
		Checksum: "curr000000000",
		Findings: []snapshot.SnapshotFinding{
			{RuleID: "exposed_inference", Severity: "HIGH", File: "compose.yml", Message: "port open", Hash: "hash_a"},
			{RuleID: "privileged_container", Severity: "CRITICAL", File: "compose.yml", Message: "privileged", Hash: "hash_c"},
		},
	}

	bp := writeSnapshot(t, dir, "base.json", base)
	cp := writeSnapshot(t, dir, "current.json", current)

	cl, err := GenerateChangelog(bp, cp)
	if err != nil {
		t.Fatal(err)
	}
	if len(cl.NewFindings) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(cl.NewFindings))
	}
	if cl.NewFindings[0].RuleID != "privileged_container" {
		t.Errorf("expected new finding privileged_container, got %s", cl.NewFindings[0].RuleID)
	}
	if len(cl.Resolved) != 1 {
		t.Fatalf("expected 1 resolved, got %d", len(cl.Resolved))
	}
	if cl.Resolved[0].RuleID != "latest_image" {
		t.Errorf("expected resolved latest_image, got %s", cl.Resolved[0].RuleID)
	}
	if !strings.Contains(cl.Summary, "1 new") {
		t.Errorf("summary missing new count: %s", cl.Summary)
	}
	if !strings.Contains(cl.Summary, "1 resolved") {
		t.Errorf("summary missing resolved count: %s", cl.Summary)
	}
}

func TestGenerateChangelogSeverityChange(t *testing.T) {
	dir := t.TempDir()
	base := snapshot.Snapshot{
		Checksum: "base000000000",
		Findings: []snapshot.SnapshotFinding{
			{RuleID: "exposed_inference", Severity: "MEDIUM", File: "compose.yml", Message: "port open", Hash: "hash_a"},
		},
	}
	current := snapshot.Snapshot{
		Checksum: "curr000000000",
		Findings: []snapshot.SnapshotFinding{
			{RuleID: "exposed_inference", Severity: "HIGH", File: "compose.yml", Message: "port open", Hash: "hash_a"},
		},
	}

	bp := writeSnapshot(t, dir, "base.json", base)
	cp := writeSnapshot(t, dir, "current.json", current)

	cl, err := GenerateChangelog(bp, cp)
	if err != nil {
		t.Fatal(err)
	}
	if len(cl.Changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(cl.Changes))
	}
	if cl.Changes[0].Type != "severity_change" {
		t.Errorf("expected severity_change type, got %s", cl.Changes[0].Type)
	}
	if !strings.Contains(cl.Changes[0].Message, "MEDIUM") || !strings.Contains(cl.Changes[0].Message, "HIGH") {
		t.Errorf("expected severity change message, got %s", cl.Changes[0].Message)
	}
}

func TestFormatMarkdown(t *testing.T) {
	cl := Changelog{
		FromSnapshot: "abcdef1234567890",
		ToSnapshot:   "fedcba0987654321",
		Timestamp:    "2025-01-15T10:00:00Z",
		Summary:      "1 new finding(s), 1 resolved",
		NewFindings: []ChangeEntry{
			{Type: "new_finding", RuleID: "privileged_container", Severity: "CRITICAL", File: "compose.yml", Message: "privileged: true"},
		},
		Resolved: []ChangeEntry{
			{Type: "resolved", RuleID: "latest_image", Severity: "MEDIUM", File: "compose.yml", Message: "uses latest"},
		},
	}

	md := FormatMarkdown(cl)
	if !strings.Contains(md, "# Security Changelog") {
		t.Error("missing header")
	}
	if !strings.Contains(md, "abcdef123456") {
		t.Error("missing truncated from-snapshot")
	}
	if !strings.Contains(md, "## New Findings") {
		t.Error("missing new findings section")
	}
	if !strings.Contains(md, "## Resolved") {
		t.Error("missing resolved section")
	}
	if !strings.Contains(md, "privileged_container") {
		t.Error("missing new finding rule ID")
	}
	if !strings.Contains(md, "~~") {
		t.Error("resolved items should use strikethrough")
	}
}

func TestFormatText(t *testing.T) {
	cl := Changelog{
		FromSnapshot: "abcdef1234567890",
		ToSnapshot:   "fedcba0987654321",
		Timestamp:    "2025-01-15T10:00:00Z",
		Summary:      "2 new finding(s)",
		NewFindings: []ChangeEntry{
			{Type: "new_finding", RuleID: "r1", Severity: "HIGH", File: "a.yml", Message: "msg1"},
			{Type: "new_finding", RuleID: "r2", Severity: "MEDIUM", File: "b.yml", Message: "msg2"},
		},
	}

	txt := FormatText(cl)
	if !strings.Contains(txt, "Security Changelog") {
		t.Error("missing header")
	}
	if !strings.Contains(txt, "New Findings (2)") {
		t.Error("missing new findings count")
	}
	if !strings.Contains(txt, "+ [HIGH]") {
		t.Error("missing finding prefix")
	}
}

func TestFormatMarkdownEmpty(t *testing.T) {
	cl := Changelog{
		FromSnapshot: "aaa",
		ToSnapshot:   "bbb",
		Timestamp:    "2025-01-01T00:00:00Z",
		Summary:      "No changes detected.",
	}
	md := FormatMarkdown(cl)
	if !strings.Contains(md, "No changes detected.") {
		t.Error("missing summary for empty changelog")
	}
	if strings.Contains(md, "## New Findings") {
		t.Error("should not have new findings section when empty")
	}
}

func TestGenerateChangelogBadPath(t *testing.T) {
	_, err := GenerateChangelog("/nonexistent/base.json", "/nonexistent/current.json")
	if err == nil {
		t.Error("expected error for nonexistent files")
	}
}

func TestShort(t *testing.T) {
	if s := short("abcdef1234567890ffff"); s != "abcdef123456" {
		t.Errorf("expected truncation to 12 chars, got %q", s)
	}
	if s := short("short"); s != "short" {
		t.Errorf("expected no truncation for short string, got %q", s)
	}
}
