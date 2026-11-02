package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotModTimes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services:\n  web:\n    image: nginx\n"), 0644); err != nil {
		t.Fatal(err)
	}

	snap := snapshotModTimes(dir)
	if len(snap) != 1 {
		t.Fatalf("expected 1 file, got %d", len(snap))
	}
	if _, ok := snap["docker-compose.yml"]; !ok {
		t.Error("expected docker-compose.yml in snapshot")
	}
}

func TestSnapshotSkipsDotTasiaAndGit(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{".tasia", ".git"} {
		p := filepath.Join(dir, sub)
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "data.json"), []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services:\n  web:\n    image: nginx\n"), 0644); err != nil {
		t.Fatal(err)
	}

	snap := snapshotModTimes(dir)
	if len(snap) != 1 {
		t.Errorf("expected 1 file (only docker-compose.yml), got %d: %v", len(snap), snap)
	}
}

func TestModTimesEqual(t *testing.T) {
	now := time.Now()
	a := map[string]time.Time{"f1": now, "f2": now.Add(time.Second)}
	b := map[string]time.Time{"f1": now, "f2": now.Add(time.Second)}
	if !modTimesEqual(a, b) {
		t.Error("identical maps should be equal")
	}

	c := map[string]time.Time{"f1": now, "f2": now.Add(2 * time.Second)}
	if modTimesEqual(a, c) {
		t.Error("different mod times should not be equal")
	}

	d := map[string]time.Time{"f1": now}
	if modTimesEqual(a, d) {
		t.Error("different lengths should not be equal")
	}

	e := map[string]time.Time{"f1": now, "f3": now.Add(time.Second)}
	if modTimesEqual(a, e) {
		t.Error("different keys should not be equal")
	}
}

func TestModTimesEqualEmpty(t *testing.T) {
	if !modTimesEqual(map[string]time.Time{}, map[string]time.Time{}) {
		t.Error("two empty maps should be equal")
	}
}

func TestRunScanCleanDir(t *testing.T) {
	dir := t.TempDir()
	compose := `services:
  web:
    image: nginx:1.25
    ports:
      - "127.0.0.1:8080:80"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result := RunScan(dir, "")
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.Decision == "" {
		t.Error("expected a decision")
	}
}

func TestRunScanDetectsFindings(t *testing.T) {
	dir := t.TempDir()
	compose := `services:
  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}

	result := RunScan(dir, "high")
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for exposed ollama")
	}
}

func TestRunScanEmptyDir(t *testing.T) {
	dir := t.TempDir()
	result := RunScan(dir, "")
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings for empty dir, got %d", len(result.Findings))
	}
}

func TestSnapshotDetectsChange(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(f, []byte("services:\n  web:\n    image: nginx\n"), 0644); err != nil {
		t.Fatal(err)
	}

	before := snapshotModTimes(dir)

	// Ensure mod time advances (some filesystems have 1s granularity)
	time.Sleep(50 * time.Millisecond)
	now := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(f, now, now); err != nil {
		t.Fatal(err)
	}

	after := snapshotModTimes(dir)
	if modTimesEqual(before, after) {
		t.Error("snapshots should differ after file modification")
	}
}
