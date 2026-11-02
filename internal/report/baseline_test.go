package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestLoadBaseline(t *testing.T) {
	sarif := `{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "tasia", "version": "0.1.0"}},
    "results": [
      {
        "ruleId": "exposed_inference",
        "level": "error",
        "message": {"text": "Inference API published"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "docker-compose.yml"},
            "region": {"startLine": 5}
          }
        }]
      },
      {
        "ruleId": "latest_image",
        "level": "warning",
        "message": {"text": "Image uses latest tag"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "docker-compose.yml"},
            "region": {"startLine": 3}
          }
        }]
      }
    ]
  }]
}`
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.sarif")
	if err := os.WriteFile(path, []byte(sarif), 0644); err != nil {
		t.Fatal(err)
	}

	keys, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 baseline keys, got %d", len(keys))
	}
	if !keys[baselineKey{RuleID: "exposed_inference", File: "docker-compose.yml", Line: 5}] {
		t.Error("missing exposed_inference key")
	}
	if !keys[baselineKey{RuleID: "latest_image", File: "docker-compose.yml", Line: 3}] {
		t.Error("missing latest_image key")
	}
}

func TestFilterBaseline(t *testing.T) {
	baseline := map[baselineKey]bool{
		{RuleID: "exposed_inference", File: "docker-compose.yml", Line: 5}: true,
		{RuleID: "latest_image", File: "docker-compose.yml", Line: 3}:     true,
	}

	findings := []rules.Finding{
		{ID: "exposed_inference", File: "docker-compose.yml", Line: 5, Title: "old finding"},
		{ID: "latest_image", File: "docker-compose.yml", Line: 3, Title: "old finding"},
		{ID: "docker_socket_mount", File: "docker-compose.yml", Line: 10, Title: "new finding"},
		{ID: "exposed_inference", File: "other.yml", Line: 5, Title: "new location"},
	}

	kept, suppressed := FilterBaseline(findings, baseline)
	if suppressed != 2 {
		t.Fatalf("expected 2 suppressed, got %d", suppressed)
	}
	if len(kept) != 2 {
		t.Fatalf("expected 2 kept, got %d", len(kept))
	}
	if kept[0].ID != "docker_socket_mount" {
		t.Errorf("expected docker_socket_mount first, got %s", kept[0].ID)
	}
	if kept[1].ID != "exposed_inference" || kept[1].File != "other.yml" {
		t.Errorf("expected exposed_inference in other.yml, got %s in %s", kept[1].ID, kept[1].File)
	}
}

func TestFilterBaselineEmpty(t *testing.T) {
	findings := []rules.Finding{
		{ID: "exposed_inference", File: "compose.yml", Line: 5},
	}
	kept, suppressed := FilterBaseline(findings, nil)
	if suppressed != 0 {
		t.Fatalf("expected 0 suppressed with nil baseline, got %d", suppressed)
	}
	if len(kept) != 1 {
		t.Fatalf("expected 1 kept, got %d", len(kept))
	}
}

func TestLoadBaselineFileNotFound(t *testing.T) {
	_, err := LoadBaseline("/nonexistent/baseline.sarif")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
