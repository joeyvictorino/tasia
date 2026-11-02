package imageage

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalImages != 0 {
		t.Errorf("empty input should have 0 images, got %d", r.Summary.TotalImages)
	}
}

func TestAnalyzeEOLImage(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "app", Image: "python:2.7"},
				},
			},
		},
	}

	r := Analyze(collected)
	if len(r.Images) != 1 {
		t.Fatalf("expected 1 image, got %d", len(r.Images))
	}
	if r.Images[0].Staleness != StaleEOL {
		t.Errorf("python:2.7 should be eol, got %s", r.Images[0].Staleness)
	}
	if r.Images[0].MajorVer != 2 {
		t.Errorf("major version should be 2, got %d", r.Images[0].MajorVer)
	}
}

func TestAnalyzeOldImage(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "compose.yml",
				Services: []compose.Service{
					{Name: "db", Image: "postgres:13"},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Images[0].Staleness != StaleOld {
		t.Errorf("postgres:13 should be old, got %s", r.Images[0].Staleness)
	}
}

func TestAnalyzeCurrentImage(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "compose.yml",
				Services: []compose.Service{
					{Name: "db", Image: "postgres:16"},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Images[0].Staleness != StaleCurrent {
		t.Errorf("postgres:16 should be current, got %s", r.Images[0].Staleness)
	}
}

func TestAnalyzeLatestTag(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx:latest"},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Images[0].Staleness != StaleUnknown {
		t.Errorf("nginx:latest should be unknown, got %s", r.Images[0].Staleness)
	}
	if r.Summary.LatestTag != 1 {
		t.Errorf("expected 1 latest tag, got %d", r.Summary.LatestTag)
	}
}

func TestAnalyzeNoTag(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx"},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Images[0].Staleness != StaleUnknown {
		t.Errorf("untagged image should be unknown, got %s", r.Images[0].Staleness)
	}
	if r.Summary.NoTag != 1 {
		t.Errorf("expected 1 no-tag, got %d", r.Summary.NoTag)
	}
}

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		input    string
		registry string
		name     string
		tag      string
	}{
		{"nginx:1.25", "", "nginx", "1.25"},
		{"library/nginx:latest", "", "library/nginx", "latest"},
		{"ghcr.io/owner/repo:v1.2.3", "ghcr.io", "owner/repo", "v1.2.3"},
		{"postgres", "", "postgres", ""},
		{"myregistry.com:5000/myimage:tag", "myregistry.com:5000", "myimage", "tag"},
	}

	for _, tt := range tests {
		reg, name, tag := parseImageRef(tt.input)
		if reg != tt.registry || name != tt.name || tag != tt.tag {
			t.Errorf("parseImageRef(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tt.input, reg, name, tag, tt.registry, tt.name, tt.tag)
		}
	}
}

func TestSortOrder(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "compose.yml",
				Services: []compose.Service{
					{Name: "current", Image: "postgres:16"},
					{Name: "eol", Image: "python:2.7"},
					{Name: "old", Image: "node:16.0"},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Images[0].Staleness != StaleEOL {
		t.Error("EOL images should sort first")
	}
	if r.Images[len(r.Images)-1].Staleness != StaleCurrent {
		t.Error("current images should sort last")
	}
}

func TestFormatText(t *testing.T) {
	r := Report{
		Images: []ImageAnalysis{
			{Service: "app", Image: "python:2.7", Staleness: StaleEOL, Reason: "eol"},
		},
		Summary: Summary{TotalImages: 1, UniqueImages: 1, ByStaleness: map[string]int{"eol": 1}},
	}

	text := FormatText(r)
	if !strings.Contains(text, "Image Age Analysis") {
		t.Error("should contain header")
	}
	if !strings.Contains(text, "python:2.7") {
		t.Error("should contain image name")
	}
}
