package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareRequiresPaths(t *testing.T) {
	err := Run([]string{"compare"})
	if err == nil {
		t.Error("compare should fail without --paths")
	}
}

func TestCompareRequiresMultiplePaths(t *testing.T) {
	dir := t.TempDir()
	err := Run([]string{"compare", "--paths", dir})
	if err == nil {
		t.Error("compare should fail with only 1 directory")
	}
}

func TestCompareEmptyDirs(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	result := compareProjects([]string{dir1, dir2})

	if result.TotalProjects != 2 {
		t.Errorf("expected 2 projects, got %d", result.TotalProjects)
	}
	if len(result.CommonRules) != 0 {
		t.Errorf("expected 0 common rules, got %d", len(result.CommonRules))
	}
}

func TestCompareWithFindings(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	compose1 := `services:
  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
    privileged: true
`
	compose2 := `services:
  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
`

	if err := os.WriteFile(filepath.Join(dir1, "docker-compose.yml"), []byte(compose1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "docker-compose.yml"), []byte(compose2), 0o644); err != nil {
		t.Fatal(err)
	}

	result := compareProjects([]string{dir1, dir2})

	if result.TotalProjects != 2 {
		t.Fatalf("expected 2 projects, got %d", result.TotalProjects)
	}

	if result.Projects[0].Count == 0 {
		t.Error("project 1 should have findings")
	}
	if result.Projects[1].Count == 0 {
		t.Error("project 2 should have findings")
	}

	hasCommon := false
	for _, r := range result.CommonRules {
		if r == "exposed_inference" {
			hasCommon = true
		}
	}
	if !hasCommon {
		t.Error("exposed_inference should be a common rule")
	}
}

func TestCompareJSONFormat(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	err := Run([]string{"compare", "--paths", dir1 + "," + dir2, "--format", "json"})
	if err != nil {
		t.Fatalf("compare json failed: %v", err)
	}
}

func TestCompareFindCommonRules(t *testing.T) {
	rules := map[string]map[string]bool{
		"a": {"r1": true, "r2": true, "r3": true},
		"b": {"r1": true, "r3": true},
		"c": {"r1": true, "r2": true, "r3": true, "r4": true},
	}
	common := findCommonRules(rules)

	if len(common) != 2 {
		t.Fatalf("expected 2 common rules, got %d: %v", len(common), common)
	}
	found := strings.Join(common, ",")
	if !strings.Contains(found, "r1") || !strings.Contains(found, "r3") {
		t.Errorf("expected r1 and r3 in common, got %s", found)
	}
}

func TestCompareFindUniqueRules(t *testing.T) {
	rules := map[string]map[string]bool{
		"a": {"r1": true, "r2": true},
		"b": {"r1": true, "r3": true},
	}
	common := findCommonRules(rules)
	unique := findUniqueRules(rules, common)

	if aUnique, ok := unique["a"]; !ok || len(aUnique) != 1 || aUnique[0] != "r2" {
		t.Errorf("project a should have unique rule r2, got %v", unique["a"])
	}
	if bUnique, ok := unique["b"]; !ok || len(bUnique) != 1 || bUnique[0] != "r3" {
		t.Errorf("project b should have unique rule r3, got %v", unique["b"])
	}
}
