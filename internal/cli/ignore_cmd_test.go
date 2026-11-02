package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIgnoreListEmpty(t *testing.T) {
	dir := t.TempDir()
	err := runIgnoreCmd([]string{"list", "--path", dir})
	if err != nil {
		t.Fatalf("ignore list on empty dir: %v", err)
	}
}

func TestIgnoreListJSON(t *testing.T) {
	dir := t.TempDir()
	err := runIgnoreCmd([]string{"list", "--path", dir, "--format", "json"})
	if err != nil {
		t.Fatalf("ignore list json: %v", err)
	}
}

func TestIgnoreAdd(t *testing.T) {
	dir := t.TempDir()
	err := runIgnoreCmd([]string{"add", "--path", dir, "--pattern", "vendor/"})
	if err != nil {
		t.Fatalf("ignore add: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".tasiaignore"))
	if err != nil {
		t.Fatalf("read .tasiaignore: %v", err)
	}
	if !strings.Contains(string(data), "vendor/") {
		t.Fatal("expected vendor/ in .tasiaignore")
	}
}

func TestIgnoreAddDuplicate(t *testing.T) {
	dir := t.TempDir()
	if err := runIgnoreCmd([]string{"add", "--path", dir, "--pattern", "dist/"}); err != nil {
		t.Fatal(err)
	}
	if err := runIgnoreCmd([]string{"add", "--path", dir, "--pattern", "dist/"}); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, ".tasiaignore"))
	if strings.Count(string(data), "dist/") != 1 {
		t.Fatal("expected exactly one dist/ entry")
	}
}

func TestIgnoreAddMissingPattern(t *testing.T) {
	dir := t.TempDir()
	err := runIgnoreCmd([]string{"add", "--path", dir})
	if err == nil {
		t.Fatal("expected error for missing --pattern")
	}
}

func TestIgnoreRemove(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".tasiaignore"), []byte("vendor/\ndist/\n"), 0644)

	err := runIgnoreCmd([]string{"remove", "--path", dir, "--pattern", "vendor/"})
	if err != nil {
		t.Fatalf("ignore remove: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, ".tasiaignore"))
	if strings.Contains(string(data), "vendor/") {
		t.Fatal("expected vendor/ to be removed")
	}
	if !strings.Contains(string(data), "dist/") {
		t.Fatal("expected dist/ to remain")
	}
}

func TestIgnoreRemoveNotFound(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".tasiaignore"), []byte("vendor/\n"), 0644)

	err := runIgnoreCmd([]string{"remove", "--path", dir, "--pattern", "nonexistent"})
	if err == nil {
		t.Fatal("expected error for missing pattern")
	}
}

func TestIgnoreRemoveMissingPattern(t *testing.T) {
	dir := t.TempDir()
	err := runIgnoreCmd([]string{"remove", "--path", dir})
	if err == nil {
		t.Fatal("expected error for missing --pattern")
	}
}

func TestIgnoreListAfterAddRemove(t *testing.T) {
	dir := t.TempDir()
	runIgnoreCmd([]string{"add", "--path", dir, "--pattern", "vendor/"})
	runIgnoreCmd([]string{"add", "--path", dir, "--pattern", "dist/"})
	runIgnoreCmd([]string{"add", "--path", dir, "--pattern", "node_modules/"})
	runIgnoreCmd([]string{"remove", "--path", dir, "--pattern", "dist/"})

	err := runIgnoreCmd([]string{"list", "--path", dir})
	if err != nil {
		t.Fatalf("ignore list: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, ".tasiaignore"))
	content := string(data)
	if !strings.Contains(content, "vendor/") || !strings.Contains(content, "node_modules/") {
		t.Fatal("expected vendor/ and node_modules/ to remain")
	}
	if strings.Contains(content, "dist/") {
		t.Fatal("expected dist/ to be removed")
	}
}

func TestIgnoreUnknownSubcommand(t *testing.T) {
	err := runIgnoreCmd([]string{"frobnicate"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

func TestIgnoreDefaultSubcommand(t *testing.T) {
	err := runIgnoreCmd(nil)
	if err != nil {
		t.Fatalf("ignore with no args: %v", err)
	}
}

func TestReadIgnoreFileComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".tasiaignore")
	os.WriteFile(path, []byte("# comment\nvendor/\n\n# another\ndist/\n"), 0644)

	entries, err := readIgnoreFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Pattern != "vendor/" || entries[1].Pattern != "dist/" {
		t.Fatalf("wrong patterns: %v", entries)
	}
}
