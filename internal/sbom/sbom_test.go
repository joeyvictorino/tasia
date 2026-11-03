package sbom

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestGenerateSBOMEmpty(t *testing.T) {
	c := &collect.Collected{}
	s := GenerateSBOM("/tmp", c)
	if s.Summary.Total != 0 {
		t.Errorf("expected 0 components, got %d", s.Summary.Total)
	}
	if s.Format != "tasia-sbom-1.0" {
		t.Errorf("unexpected format: %s", s.Format)
	}
}

func TestGenerateSBOMDockerImages(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx:1.25"},
					{Name: "db", Image: "postgres:16.1"},
					{Name: "cache", Image: "redis"},
				},
			},
		},
	}
	s := GenerateSBOM("/test", c)
	if s.Summary.Total != 3 {
		t.Errorf("expected 3 components, got %d", s.Summary.Total)
	}
	if s.Summary.ByType["container-image"] != 3 {
		t.Errorf("expected 3 container-image, got %d", s.Summary.ByType["container-image"])
	}
	if s.Summary.Unpinned != 1 {
		t.Errorf("expected 1 unpinned (redis), got %d", s.Summary.Unpinned)
	}
}

func TestGenerateSBOMDedup(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web1", Image: "nginx:1.25"},
					{Name: "web2", Image: "nginx:1.25"},
				},
			},
		},
	}
	s := GenerateSBOM("/test", c)
	if s.Summary.Total != 1 {
		t.Errorf("expected 1 deduplicated component, got %d", s.Summary.Total)
	}
}

func TestGenerateSBOMPURL(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx:1.25"},
				},
			},
		},
	}
	s := GenerateSBOM("/test", c)
	if len(s.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(s.Components))
	}
	if s.Components[0].PkgURL != "pkg:docker/nginx@1.25" {
		t.Errorf("unexpected purl: %s", s.Components[0].PkgURL)
	}
}

func TestGenerateSBOMDigestPinned(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd"},
				},
			},
		},
	}
	s := GenerateSBOM("/test", c)
	if s.Summary.Unpinned != 0 {
		t.Errorf("digest should be pinned, got %d unpinned", s.Summary.Unpinned)
	}
}

func TestFormatText(t *testing.T) {
	s := SBOM{
		Format:    "tasia-sbom-1.0",
		ScanPath:  "/test",
		Timestamp: "2024-01-01T00:00:00Z",
		Components: []Component{
			{Name: "nginx", Version: "1.25", Type: "container-image", Source: "docker-compose.yml"},
		},
		Summary: SBOMSummary{Total: 1, ByType: map[string]int{"container-image": 1}, Unpinned: 0},
	}
	text := FormatText(s)
	if !strings.Contains(text, "nginx") {
		t.Error("expected nginx in text output")
	}
	if !strings.Contains(text, "1 components") {
		t.Error("expected component count in text output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	s := SBOM{
		Summary: SBOMSummary{Total: 0, ByType: map[string]int{}},
	}
	text := FormatText(s)
	if !strings.Contains(text, "No components found") {
		t.Error("expected 'No components found' for empty SBOM")
	}
}

func TestToSPDXLite(t *testing.T) {
	s := SBOM{
		Timestamp: "2024-01-01T00:00:00Z",
		Components: []Component{
			{Name: "nginx", Version: "1.25", Type: "container-image", PkgURL: "pkg:docker/nginx@1.25"},
			{Name: "postgres", Version: "16", Type: "container-image", PkgURL: "pkg:docker/postgres@16"},
		},
	}
	spdx := ToSPDXLite(s)
	if spdx.SPDXVersion != "SPDX-2.3" {
		t.Errorf("unexpected SPDX version: %s", spdx.SPDXVersion)
	}
	if len(spdx.Packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(spdx.Packages))
	}
	if spdx.Packages[0].ExternalRefs[0].ReferenceLocator != "pkg:docker/nginx@1.25" {
		t.Errorf("unexpected purl: %s", spdx.Packages[0].ExternalRefs[0].ReferenceLocator)
	}
}

func TestIsPinned(t *testing.T) {
	cases := []struct {
		version string
		pinned  bool
	}{
		{"1.25", true},
		{"v2.0.1", true},
		{"latest", false},
		{"", false},
		{"sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd", true},
		{"alpine", false},
	}
	for _, tc := range cases {
		got := isPinned(tc.version)
		if got != tc.pinned {
			t.Errorf("isPinned(%q) = %v, want %v", tc.version, got, tc.pinned)
		}
	}
}

func TestParseImageRef(t *testing.T) {
	cases := []struct {
		ref  string
		img  string
		tag  string
	}{
		{"nginx:1.25", "nginx", "1.25"},
		{"nginx", "nginx", ""},
		{"nginx@sha256:abcd", "nginx", "sha256:abcd"},
		{"registry.example.com/app:v1.0", "registry.example.com/app", "v1.0"},
	}
	for _, tc := range cases {
		img, tag := parseImageRef(tc.ref)
		if img != tc.img || tag != tc.tag {
			t.Errorf("parseImageRef(%q) = (%q, %q), want (%q, %q)", tc.ref, img, tag, tc.img, tc.tag)
		}
	}
}
