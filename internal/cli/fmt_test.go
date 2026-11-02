package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFmtNormalizesOutput(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".tasiarc.yaml")

	messy := "severities:\n  privileged_container: HIGH\n  exposed_inference: low\n"
	if err := os.WriteFile(rcPath, []byte(messy), 0o644); err != nil {
		t.Fatal(err)
	}

	err := Run([]string{"fmt", "--path", rcPath})
	if err != nil {
		t.Fatalf("fmt returned error: %v", err)
	}

	data, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "privileged_container: high") {
		t.Error("should normalize severity to lowercase")
	}
	if !strings.Contains(content, "exposed_inference: low") {
		t.Error("should preserve user overrides")
	}
	if !strings.Contains(content, "# --- compose ---") {
		t.Error("should contain category headers")
	}
}

func TestFmtCheckDetectsChanges(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".tasiarc.yaml")

	messy := "severities:\n  privileged_container: HIGH\n"
	if err := os.WriteFile(rcPath, []byte(messy), 0o644); err != nil {
		t.Fatal(err)
	}

	// --check should detect that formatting would change the file.
	// We can't easily test os.Exit(1) so we use formatConfig directly.
	original, _ := os.ReadFile(rcPath)
	formatted, err := formatConfig(original)
	if err != nil {
		t.Fatal(err)
	}
	if string(original) == formatted {
		t.Error("messy config should differ from formatted version")
	}
}

func TestFmtCheckPassesOnFormatted(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".tasiarc.yaml")

	// Create a formatted config via init, then fmt it
	if err := Run([]string{"init", "--path", dir}); err != nil {
		t.Fatal(err)
	}

	original, _ := os.ReadFile(rcPath)
	formatted, err := formatConfig(original)
	if err != nil {
		t.Fatal(err)
	}

	// Format the formatted output again — should be idempotent
	reformatted, err := formatConfig([]byte(formatted))
	if err != nil {
		t.Fatal(err)
	}
	if formatted != reformatted {
		t.Error("formatting should be idempotent")
	}
}

func TestFmtDiffShowsChanges(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".tasiarc.yaml")

	messy := "severities:\n  privileged_container: HIGH\n"
	if err := os.WriteFile(rcPath, []byte(messy), 0o644); err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := Run([]string{"fmt", "--path", rcPath, "--diff"})

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("fmt --diff returned error: %v", err)
	}

	buf := make([]byte, 16384)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "+") && !strings.Contains(output, "-") {
		t.Error("diff output should contain + or - lines")
	}
}

func TestFmtPreservesUnknownKeys(t *testing.T) {
	input := "severities:\n  custom_unknown_rule: medium\n"
	formatted, err := formatConfig([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(formatted, "custom_unknown_rule: medium") {
		t.Error("should preserve unknown rule overrides")
	}
	if !strings.Contains(formatted, "unknown (not in current catalog)") {
		t.Error("should label unknown rules")
	}
}
