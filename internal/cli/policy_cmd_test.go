package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunPolicyNoArgs(t *testing.T) {
	err := runPolicy(nil)
	if err != nil {
		t.Fatalf("policy with no args should not error: %v", err)
	}
}

func TestRunPolicyJSON(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "policy.json")
	err := runPolicy([]string{"--format", "json", "--output", out})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("output file should not be empty")
	}
}

func TestRunPolicyMarkdown(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "policy.md")
	err := runPolicy([]string{"--format", "markdown", "--output", out, "--title", "My Policy"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(out)
	if len(data) == 0 {
		t.Error("output file should not be empty")
	}
}

func TestRunPolicyText(t *testing.T) {
	err := runPolicy([]string{"--format", "text"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
