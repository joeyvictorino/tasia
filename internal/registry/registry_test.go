package registry

import (
	"encoding/json"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeLatestTag(t *testing.T) {
	c := collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM nginx:latest\nRUN apt-get update",
			},
		},
	}
	r := Analyze(&c)
	if r.Summary.LatestTags != 1 {
		t.Errorf("expected 1 latest tag, got %d", r.Summary.LatestTags)
	}
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "registry_latest_tag" {
			found = true
		}
	}
	if !found {
		t.Error("expected registry_latest_tag finding")
	}
}

func TestAnalyzeNoDigest(t *testing.T) {
	c := collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM nginx:1.25",
			},
		},
	}
	r := Analyze(&c)
	if r.Summary.UnpinnedImages != 1 {
		t.Errorf("expected 1 unpinned image, got %d", r.Summary.UnpinnedImages)
	}
}

func TestAnalyzeDigestPinned(t *testing.T) {
	c := collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM nginx:1.25@sha256:abcdef1234567890",
			},
		},
	}
	r := Analyze(&c)
	if r.Summary.UnpinnedImages != 0 {
		t.Errorf("expected 0 unpinned images, got %d", r.Summary.UnpinnedImages)
	}
}

func TestAnalyzeUntrustedRegistry(t *testing.T) {
	c := collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM evil.registry.io/malware:1.0",
			},
		},
	}
	r := Analyze(&c)
	if r.Summary.UntrustedRegs != 1 {
		t.Errorf("expected 1 untrusted, got %d", r.Summary.UntrustedRegs)
	}
}

func TestAnalyzeTrustedRegistry(t *testing.T) {
	c := collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM gcr.io/myproject/app:1.0@sha256:abc123",
			},
		},
	}
	r := Analyze(&c)
	if r.Summary.UntrustedRegs != 0 {
		t.Errorf("expected 0 untrusted, got %d", r.Summary.UntrustedRegs)
	}
}

func TestAnalyzeComposeService(t *testing.T) {
	c := collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx:latest"},
					{Name: "db", Image: "postgres:15"},
				},
			},
		},
	}
	r := Analyze(&c)
	if r.Summary.TotalImages != 2 {
		t.Errorf("expected 2 images, got %d", r.Summary.TotalImages)
	}
	if r.Summary.LatestTags != 1 {
		t.Errorf("expected 1 latest tag, got %d", r.Summary.LatestTags)
	}
}

func TestParseImageThreePartRegistry(t *testing.T) {
	img := ParseImage("gcr.io/myproject/app:1.0")
	if img.Registry != "gcr.io" {
		t.Errorf("expected gcr.io, got %s", img.Registry)
	}
	if img.Tag != "1.0" {
		t.Errorf("expected tag 1.0, got %s", img.Tag)
	}
}

func TestParseImageDockerHub(t *testing.T) {
	img := ParseImage("nginx:1.25")
	if img.Registry != "docker.io" {
		t.Errorf("expected docker.io, got %s", img.Registry)
	}
	if img.Tag != "1.25" {
		t.Errorf("expected tag 1.25, got %s", img.Tag)
	}
}

func TestParseImageWithDigest(t *testing.T) {
	img := ParseImage("nginx:1.25@sha256:abc123")
	if img.Digest != "sha256:abc123" {
		t.Errorf("expected digest sha256:abc123, got %s", img.Digest)
	}
}

func TestScorePerfect(t *testing.T) {
	c := collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM gcr.io/proj/app:1.0@sha256:abc123",
			},
		},
	}
	r := Analyze(&c)
	if r.Summary.Score != 100 {
		t.Errorf("expected score 100, got %d", r.Summary.Score)
	}
}

func TestScoreDegraded(t *testing.T) {
	c := collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{
				Path:    "Dockerfile",
				Content: "FROM evil.io/app:latest",
			},
		},
	}
	r := Analyze(&c)
	if r.Summary.Score >= 100 {
		t.Errorf("expected degraded score, got %d", r.Summary.Score)
	}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalImages != 0 {
		t.Errorf("expected 0 images, got %d", r.Summary.TotalImages)
	}
	if r.Summary.Score != 100 {
		t.Errorf("expected score 100 for empty, got %d", r.Summary.Score)
	}
}

func TestFormatText(t *testing.T) {
	c := collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{Path: "Dockerfile", Content: "FROM nginx:latest"},
		},
	}
	r := Analyze(&c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collect.Collected{
		Dockerfiles: []collect.Dockerfile{
			{Path: "Dockerfile", Content: "FROM nginx:1.25"},
		},
	}
	r := Analyze(&c)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Summary.TotalImages != r.Summary.TotalImages {
		t.Error("image count mismatch after JSON round-trip")
	}
}
