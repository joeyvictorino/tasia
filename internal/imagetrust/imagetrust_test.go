package imagetrust

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func col(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}},
	}
}

func TestEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestLatestTag(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "app", Image: "nginx:latest", ImageLine: 3}))
	if r.Services[0].TrustLevel != TrustLatest {
		t.Fatalf("expected latest trust, got %s", r.Services[0].TrustLevel)
	}
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "mutable_latest_tag" && f.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected mutable_latest_tag finding")
	}
	if r.Summary.LatestCount != 1 {
		t.Fatalf("expected 1 latest, got %d", r.Summary.LatestCount)
	}
}

func TestImplicitLatest(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "app", Image: "nginx"}))
	if r.Services[0].TrustLevel != TrustLatest {
		t.Fatalf("expected latest trust for untagged image, got %s", r.Services[0].TrustLevel)
	}
}

func TestDigestPinned(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "app", Image: "nginx@sha256:abcdef1234567890"}))
	if r.Services[0].TrustLevel != TrustPinned {
		t.Fatalf("expected pinned trust, got %s", r.Services[0].TrustLevel)
	}
	if !r.Services[0].HasDigest {
		t.Fatal("expected HasDigest true")
	}
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "no_digest_pin" {
			t.Fatal("should not flag no_digest_pin for pinned image")
		}
	}
	if r.Summary.PinnedCount != 1 {
		t.Fatalf("expected 1 pinned, got %d", r.Summary.PinnedCount)
	}
}

func TestTaggedNotLatest(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "db", Image: "postgres:15.2"}))
	if r.Services[0].TrustLevel != TrustTagged {
		t.Fatalf("expected tagged trust, got %s", r.Services[0].TrustLevel)
	}
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "mutable_latest_tag" {
			t.Fatal("should not flag mutable_latest_tag for versioned tag")
		}
	}
}

func TestNoImage(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "build-only"}))
	if r.Services[0].TrustLevel != TrustUnspecified {
		t.Fatalf("expected unspecified trust, got %s", r.Services[0].TrustLevel)
	}
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "no_image_specified" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected no_image_specified finding")
	}
	if r.Summary.UntaggedCount != 1 {
		t.Fatalf("expected 1 untagged, got %d", r.Summary.UntaggedCount)
	}
}

func TestUnofficialRegistry(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "app", Image: "myregistry.internal:5000/myapp:v1"}))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "unofficial_registry" && f.Severity == "medium" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected unofficial_registry finding")
	}
	if r.Summary.UnofficialCount != 1 {
		t.Fatalf("expected 1 unofficial, got %d", r.Summary.UnofficialCount)
	}
}

func TestOfficialRegistryNoFinding(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "app", Image: "ghcr.io/org/app:v2.0"}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "unofficial_registry" {
			t.Fatal("should not flag official registry ghcr.io")
		}
	}
}

func TestDockerHubOfficial(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "cache", Image: "redis:7-alpine"}))
	if r.Services[0].Registry != "docker.io" {
		t.Fatalf("expected docker.io, got %s", r.Services[0].Registry)
	}
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "unofficial_registry" {
			t.Fatal("should not flag Docker Hub as unofficial")
		}
	}
}

func TestNoDigestPin(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "app", Image: "postgres:15"}))
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "no_digest_pin" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected no_digest_pin for tag-only reference")
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(col(
		compose.Service{Name: "pinned", Image: "nginx@sha256:abc123"},
		compose.Service{Name: "latest", Image: "redis"},
		compose.Service{Name: "tagged", Image: "postgres:15"},
	))
	if r.Summary.TotalServices != 3 {
		t.Fatalf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.PinnedCount != 1 {
		t.Fatalf("expected 1 pinned, got %d", r.Summary.PinnedCount)
	}
	if r.Summary.LatestCount != 1 {
		t.Fatalf("expected 1 latest, got %d", r.Summary.LatestCount)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "app", Image: "nginx:latest"}))
	out := FormatText(r)
	if !strings.Contains(out, "Container Image Trust Analysis") {
		t.Fatal("expected header")
	}
	if !strings.Contains(out, "mutable_latest_tag") {
		t.Fatal("expected mutable_latest_tag in output")
	}
}

func TestParseImageWithPort(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "app", Image: "registry.example.com:5000/myapp:v1"}))
	if r.Services[0].Registry != "registry.example.com:5000" {
		t.Fatalf("expected registry.example.com:5000, got %s", r.Services[0].Registry)
	}
	if r.Services[0].Tag != "v1" {
		t.Fatalf("expected tag v1, got %s", r.Services[0].Tag)
	}
}

func TestAWSRegistry(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "app", Image: "123456789.dkr.ecr.us-east-1.amazonaws.com/myapp:v1"}))
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "unofficial_registry" {
			t.Fatal("should not flag AWS ECR as unofficial")
		}
	}
}
