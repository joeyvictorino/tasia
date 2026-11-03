package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUninstallNoFlag(t *testing.T) {
	err := Run([]string{"uninstall"})
	if err != nil {
		t.Fatalf("uninstall without --pre-push should print usage, not error: %v", err)
	}
}

func TestUninstallPrePushNoGit(t *testing.T) {
	dir := t.TempDir()
	// Change to a directory with no .git
	orig, _ := os.Getwd()
	defer os.Chdir(orig)
	os.Chdir(dir)

	err := Run([]string{"uninstall", "--pre-push"})
	if err == nil {
		t.Fatal("uninstall --pre-push outside git repo should error")
	}
}

func TestInstallAndUninstall(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	os.MkdirAll(gitDir, 0o755)

	orig, _ := os.Getwd()
	defer os.Chdir(orig)
	os.Chdir(dir)

	// Install
	err := Run([]string{"install", "--pre-push"})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-push")
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		t.Fatal("hook not created")
	}

	// Uninstall
	err = Run([]string{"uninstall", "--pre-push"})
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Fatal("hook not removed")
	}
}

func TestUninstallNoHook(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0o755)

	orig, _ := os.Getwd()
	defer os.Chdir(orig)
	os.Chdir(dir)

	err := Run([]string{"uninstall", "--pre-push"})
	if err != nil {
		t.Fatalf("uninstall with no hook should succeed: %v", err)
	}
}
