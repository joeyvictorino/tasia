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
		t.Fatalf("ignore list empty: %v", err)
	}
}

func TestIgnoreAdd(t *testing.T) {
	dir := t.TempDir()
	err := runIgnoreCmd([]string{"add", "--path", dir, "--pattern", "*.log"})
	if err != nil {
		t.Fatalf("ignore add: %v", err)
	}

	ignorePath := filepath.Join(dir, ".tasiaignore")
	data, err := os.ReadFile(ignorePath)
	if err != nil {
		t.Fatalf("read ignore file: %v", err)
	}
	if !strings.Contains(string(data), "*.log") {
		t.Fatalf("expected *.log in ignore file, got: %s", data)
	}
}

func TestIgnoreAddDuplicate(t *testing.T) {
	dir := t.TempDir()
	runIgnoreCmd([]string{"add", "--path", dir, "--pattern", "*.log"})
	err := runIgnoreCmd([]string{"add", "--path", dir, "--pattern", "*.log"})
	if err != nil {
		t.Fatalf("ignore add duplicate: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, ".tasiaignore"))
	if strings.Count(string(data), "*.log") != 1 {
		t.Fatalf("expected exactly one *.log, got: %s", data)
	}
}

func TestIgnoreRemove(t *testing.T) {
	dir := t.TempDir()
	runIgnoreCmd([]string{"add", "--path", dir, "--pattern", "*.log"})
	runIgnoreCmd([]string{"add", "--path", dir, "--pattern", "*.tmp"})

	err := runIgnoreCmd([]string{"remove", "--path", dir, "--pattern", "*.log"})
	if err != nil {
		t.Fatalf("ignore remove: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, ".tasiaignore"))
	if strings.Contains(string(data), "*.log") {
		t.Fatalf("*.log should be removed, got: %s", data)
	}
	if !strings.Contains(string(data), "*.tmp") {
		t.Fatalf("*.tmp should remain, got: %s", data)
	}
}

func TestIgnoreRemoveNotFound(t *testing.T) {
	dir := t.TempDir()
	runIgnoreCmd([]string{"add", "--path", dir, "--pattern", "*.log"})
	err := runIgnoreCmd([]string{"remove", "--path", dir, "--pattern", "*.xyz"})
	if err == nil {
		t.Fatal("expected error removing nonexistent pattern")
	}
}

func TestIgnoreListJSON(t *testing.T) {
	dir := t.TempDir()
	runIgnoreCmd([]string{"add", "--path", dir, "--pattern", "vendor/"})

	err := runIgnoreCmd([]string{"list", "--path", dir, "--format", "json"})
	if err != nil {
		t.Fatalf("ignore list json: %v", err)
	}
}

func TestIgnoreAddNoPattern(t *testing.T) {
	dir := t.TempDir()
	err := runIgnoreCmd([]string{"add", "--path", dir})
	if err == nil {
		t.Fatal("expected error when --pattern not provided")
	}
}

func TestIgnoreUnknownSubcmd(t *testing.T) {
	err := runIgnoreCmd([]string{"bogus"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

func TestIgnoreDefaultList(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(cwd)

	err := runIgnoreCmd(nil)
	if err != nil {
		t.Fatalf("ignore default list: %v", err)
	}
}
