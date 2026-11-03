package imagepin

import (
	"encoding/json"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestNoTag(t *testing.T) {
	c := collected(compose.Service{Name: "web", Image: "nginx"})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "image_pin_no_tag" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected image_pin_no_tag for image without tag")
	}
}

func TestLatestTag(t *testing.T) {
	c := collected(compose.Service{Name: "web", Image: "nginx:latest"})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "image_pin_latest" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected image_pin_latest for :latest tag")
	}
}

func TestMutableTag(t *testing.T) {
	c := collected(compose.Service{Name: "web", Image: "nginx:stable"})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "image_pin_mutable" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected image_pin_mutable for :stable tag")
	}
}

func TestNoDigest(t *testing.T) {
	c := collected(compose.Service{Name: "web", Image: "nginx:1.25"})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "image_pin_no_digest" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected image_pin_no_digest for image without digest")
	}
}

func TestPinnedWithDigest(t *testing.T) {
	c := collected(compose.Service{Name: "web", Image: "nginx:1.25@sha256:abc123"})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "image_pin_no_digest" {
				t.Error("should not flag when digest is present")
			}
			if f.Rule == "image_pin_no_tag" {
				t.Error("should not flag no_tag when tag is present")
			}
		}
	}
}

func TestVariableImage(t *testing.T) {
	c := collected(compose.Service{Name: "web", Image: "${MY_IMAGE}"})
	r := Analyze(c)
	for _, sr := range r.Services {
		if len(sr.Findings) > 0 {
			t.Error("should not flag variable-substituted images")
		}
	}
}

func TestEmptyImage(t *testing.T) {
	c := collected(compose.Service{Name: "web", Image: ""})
	r := Analyze(c)
	for _, sr := range r.Services {
		if len(sr.Findings) > 0 {
			t.Error("should not flag empty image (build-only service)")
		}
	}
}

func TestSummary(t *testing.T) {
	c := collected(
		compose.Service{Name: "a", Image: "nginx"},
		compose.Service{Name: "b", Image: "redis:latest"},
		compose.Service{Name: "c", Image: "postgres:15"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("total services = %d", r.Summary.TotalServices)
	}
	if r.Summary.NoTag < 1 {
		t.Error("expected no_tag count")
	}
	if r.Summary.LatestTag < 1 {
		t.Error("expected latest_tag count")
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{Name: "web", Image: "nginx"})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("empty text output")
	}
}

func TestJSON(t *testing.T) {
	c := collected(compose.Service{Name: "web", Image: "nginx:latest"})
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		input      string
		wantName   string
		wantTag    string
		wantDigest string
	}{
		{"nginx", "nginx", "", ""},
		{"nginx:1.25", "nginx", "1.25", ""},
		{"nginx:latest", "nginx", "latest", ""},
		{"nginx@sha256:abc", "nginx", "", "sha256:abc"},
		{"nginx:1.25@sha256:abc", "nginx", "1.25", "sha256:abc"},
		{"registry.io/org/img:v1", "registry.io/org/img", "v1", ""},
	}
	for _, tt := range tests {
		name, tag, digest := parseImageRef(tt.input)
		if name != tt.wantName || tag != tt.wantTag || digest != tt.wantDigest {
			t.Errorf("parseImageRef(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tt.input, name, tag, digest, tt.wantName, tt.wantTag, tt.wantDigest)
		}
	}
}
