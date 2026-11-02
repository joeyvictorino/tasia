package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateAddsNewRules(t *testing.T) {
	// An old config with only a few rules
	old := `severities:
  exposed_inference: high
  privileged_container: critical
`
	migrated, changes, err := migrateConfig_([]byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) == 0 {
		t.Fatal("should detect missing rules")
	}

	foundAdd := false
	for _, c := range changes {
		if strings.Contains(c, "new rule") {
			foundAdd = true
		}
	}
	if !foundAdd {
		t.Error("changes should mention new rules")
	}

	// Preserved overrides
	if !strings.Contains(migrated, "exposed_inference: high") {
		t.Error("should preserve user severity override")
	}
	if !strings.Contains(migrated, "privileged_container: critical") {
		t.Error("should preserve user severity override")
	}
	// Has schema version
	if !strings.Contains(migrated, "schema_version:") {
		t.Error("should add schema_version")
	}
}

func TestMigrateAlreadyCurrent(t *testing.T) {
	dir := t.TempDir()
	if err := Run([]string{"init", "--path", dir}); err != nil {
		t.Fatal(err)
	}

	rcPath := filepath.Join(dir, ".tasiarc.yaml")
	data, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatal(err)
	}

	// Add schema_version to make it "current"
	withVersion := "schema_version: \"" + currentSchemaVersion + "\"\n\n" + string(data)

	_, changes, err := migrateConfig_([]byte(withVersion))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Errorf("already-current config should have 0 changes, got %d: %v", len(changes), changes)
	}
}

func TestMigrateDryRunDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".tasiarc.yaml")

	old := "severities:\n  exposed_inference: high\n"
	if err := os.WriteFile(rcPath, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}

	err := Run([]string{"migrate", "--path", rcPath, "--dry-run"})
	if err != nil {
		t.Fatalf("migrate --dry-run returned error: %v", err)
	}

	data, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != old {
		t.Error("dry-run should not modify the file")
	}
}

func TestMigratePreservesUnknownKeys(t *testing.T) {
	old := `severities:
  custom_rule: low
  exposed_inference: high
`
	migrated, _, err := migrateConfig_([]byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(migrated, "custom_rule: low") {
		t.Error("should preserve unknown severity keys")
	}
}

func TestMigrateBumpsSchemaVersion(t *testing.T) {
	old := `schema_version: "1"
severities:
  exposed_inference: high
`
	_, changes, err := migrateConfig_([]byte(old))
	if err != nil {
		t.Fatal(err)
	}

	foundBump := false
	for _, c := range changes {
		if strings.Contains(c, "schema_version") {
			foundBump = true
		}
	}
	if !foundBump {
		t.Error("should bump schema_version")
	}
}
