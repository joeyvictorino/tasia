package cli

import (
	"testing"
)

func TestDoctorRuns(t *testing.T) {
	dir := t.TempDir()
	err := Run([]string{"doctor", "--path", dir})
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
}

func TestDoctorJSON(t *testing.T) {
	dir := t.TempDir()
	err := Run([]string{"doctor", "--path", dir, "--format", "json"})
	if err != nil {
		t.Fatalf("doctor json: %v", err)
	}
}

func TestCheckBinaryDocker(t *testing.T) {
	c := checkBinary("docker")
	if c.Name != "docker" {
		t.Errorf("name: got %q, want %q", c.Name, "docker")
	}
}

func TestCheckBinaryMissing(t *testing.T) {
	c := checkBinary("nonexistent_tool_xyz_123")
	if c.Status != "fail" {
		t.Errorf("missing binary should fail, got %q", c.Status)
	}
}

func TestCheckGitRepo(t *testing.T) {
	dir := t.TempDir()
	c := checkGitRepo(dir)
	if c.Status != "warn" {
		t.Errorf("non-git dir should warn, got %q", c.Status)
	}
}
