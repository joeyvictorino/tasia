package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindScanDirsEmpty(t *testing.T) {
	dir := t.TempDir()
	dirs := findScanDirs(dir)
	if len(dirs) != 1 || dirs[0] != dir {
		t.Errorf("empty root should return just root, got %v", dirs)
	}
}

func TestFindScanDirsNested(t *testing.T) {
	root := t.TempDir()

	// Create nested structure: root/serviceA/docker-compose.yml, root/infra/main.tf
	svcDir := filepath.Join(root, "serviceA")
	infraDir := filepath.Join(root, "infra")
	os.MkdirAll(svcDir, 0o755)
	os.MkdirAll(infraDir, 0o755)

	os.WriteFile(filepath.Join(svcDir, "docker-compose.yml"), []byte("version: '3'"), 0o644)
	os.WriteFile(filepath.Join(infraDir, "main.tf"), []byte("resource {}"), 0o644)

	dirs := findScanDirs(root)
	if len(dirs) != 3 {
		t.Fatalf("expected 3 dirs (root + serviceA + infra), got %d: %v", len(dirs), dirs)
	}

	found := map[string]bool{}
	for _, d := range dirs {
		found[d] = true
	}
	if !found[root] {
		t.Error("root should always be included")
	}
	if !found[svcDir] {
		t.Error("serviceA dir should be found")
	}
	if !found[infraDir] {
		t.Error("infra dir should be found")
	}
}

func TestFindScanDirsSkips(t *testing.T) {
	root := t.TempDir()

	// Files in skipped directories should not be found.
	nmDir := filepath.Join(root, "node_modules", "pkg")
	os.MkdirAll(nmDir, 0o755)
	os.WriteFile(filepath.Join(nmDir, "docker-compose.yml"), []byte("x"), 0o644)

	gitDir := filepath.Join(root, ".git", "hooks")
	os.MkdirAll(gitDir, 0o755)
	os.WriteFile(filepath.Join(gitDir, "Dockerfile"), []byte("FROM x"), 0o644)

	dirs := findScanDirs(root)
	if len(dirs) != 1 {
		t.Errorf("expected only root (skipped dirs), got %v", dirs)
	}
}

func TestFindScanDirsMatchesAllFileTypes(t *testing.T) {
	root := t.TempDir()

	files := map[string]string{
		"a/docker-compose.yml":      "v",
		"b/compose.yaml":            "v",
		"c/Dockerfile":              "FROM x",
		"d/.env":                    "K=V",
		"e/Caddyfile":               "x",
		"f/nginx.conf":              "x",
		"g/values.yaml":             "x",
		"h/main.tf":                 "x",
		"i/ai-stack-manifest.json":  "{}",
		"j/.env.production":         "K=V",
		"k/docker-compose.prod.yml": "v",
	}
	for rel, content := range files {
		full := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(content), 0o644)
	}

	dirs := findScanDirs(root)
	// root + 11 subdirectories
	if len(dirs) != 12 {
		t.Errorf("expected 12 dirs, got %d: %v", len(dirs), dirs)
	}
}

func TestHasScannable(t *testing.T) {
	yes := []string{
		"docker-compose.yml", "compose.yaml", "dockerfile",
		".env", ".env.production", "caddyfile", "nginx.conf",
		"values.yaml", "values.yml", "main.tf", "network.tf",
		"ai-stack-manifest.json", "docker-compose.override.yml",
	}
	for _, f := range yes {
		if !hasScannable(f) {
			t.Errorf("hasScannable(%q) should be true", f)
		}
	}

	no := []string{
		"readme.md", "main.go", "package.json", "tsconfig.json",
	}
	for _, f := range no {
		if hasScannable(f) {
			t.Errorf("hasScannable(%q) should be false", f)
		}
	}
}

func TestScanRecursiveFindsNested(t *testing.T) {
	root := t.TempDir()

	// Create a nested compose file with a known vulnerability.
	svcDir := filepath.Join(root, "apps", "inference")
	os.MkdirAll(svcDir, 0o755)

	compose := `version: "3"
services:
  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
`
	os.WriteFile(filepath.Join(svcDir, "docker-compose.yml"), []byte(compose), 0o644)

	findings := scanRecursive(root)
	if len(findings) == 0 {
		t.Fatal("expected findings from nested compose file")
	}

	// At least one finding's file path should be relative and include the nested directory.
	hasNested := false
	for _, f := range findings {
		if strings.Contains(f.File, filepath.Join("apps", "inference")) {
			hasNested = true
			break
		}
	}
	if !hasNested {
		t.Error("expected at least one finding with nested path apps/inference")
	}
}

func TestRecursiveFlagReview(t *testing.T) {
	root := t.TempDir()

	// Create a nested compose file with a finding.
	svcDir := filepath.Join(root, "svc")
	os.MkdirAll(svcDir, 0o755)

	compose := `version: "3"
services:
  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
`
	os.WriteFile(filepath.Join(svcDir, "docker-compose.yml"), []byte(compose), 0o644)

	err := Run([]string{"review", "--path", root, "--recursive", "--no-write", "--format", "json"})
	if err != nil {
		t.Fatalf("review --recursive returned error: %v", err)
	}
}

func TestRecursiveFlagCI(t *testing.T) {
	root := t.TempDir()

	// Empty monorepo: should pass CI with no findings.
	err := Run([]string{"ci", "--path", root, "--recursive"})
	if err != nil {
		t.Fatalf("ci --recursive returned error: %v", err)
	}
}

func TestSortStrings(t *testing.T) {
	ss := []string{"c", "a", "b"}
	sortStrings(ss)
	if ss[0] != "a" || ss[1] != "b" || ss[2] != "c" {
		t.Errorf("sort failed: %v", ss)
	}
}
