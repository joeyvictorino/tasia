package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunAuditTrailNoSubcommand(t *testing.T) {
	err := runAuditTrail(nil)
	if err == nil {
		t.Error("expected error with no subcommand")
	}
}

func TestRunAuditTrailUnknown(t *testing.T) {
	err := runAuditTrail([]string{"bogus"})
	if err == nil {
		t.Error("expected error for unknown subcommand")
	}
}

func TestRunAuditRecord(t *testing.T) {
	dir := t.TempDir()
	trail := filepath.Join(dir, "trail.json")
	err := runAuditTrail([]string{"record", "--trail", trail})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(trail)
	if len(data) == 0 {
		t.Error("trail file should not be empty after record")
	}
}

func TestRunAuditShow(t *testing.T) {
	dir := t.TempDir()
	trail := filepath.Join(dir, "trail.json")
	runAuditTrail([]string{"record", "--trail", trail})
	err := runAuditTrail([]string{"show", "--trail", trail})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAuditShowJSON(t *testing.T) {
	dir := t.TempDir()
	trail := filepath.Join(dir, "trail.json")
	runAuditTrail([]string{"record", "--trail", trail})
	err := runAuditTrail([]string{"show", "--trail", trail, "--format", "json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAuditLatest(t *testing.T) {
	dir := t.TempDir()
	trail := filepath.Join(dir, "trail.json")
	runAuditTrail([]string{"record", "--trail", trail})
	runAuditTrail([]string{"record", "--trail", trail})
	err := runAuditTrail([]string{"latest", "--trail", trail})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAuditLatestJSON(t *testing.T) {
	dir := t.TempDir()
	trail := filepath.Join(dir, "trail.json")
	runAuditTrail([]string{"record", "--trail", trail})
	err := runAuditTrail([]string{"latest", "--trail", trail, "--format", "json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
