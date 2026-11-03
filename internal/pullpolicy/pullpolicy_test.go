package pullpolicy

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

func svc(name, image string) compose.Service {
	return compose.Service{Name: name, Image: image}
}

func TestLatestTagDetected(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx:latest")))
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Findings))
	}
	if r.Findings[0].RuleID != "pullpolicy_latest_tag" {
		t.Errorf("expected pullpolicy_latest_tag, got %s", r.Findings[0].RuleID)
	}
	if r.Findings[0].Severity != "high" {
		t.Errorf("expected high, got %s", r.Findings[0].Severity)
	}
}

func TestNoTagDetected(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx")))
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Findings))
	}
	if r.Findings[0].RuleID != "pullpolicy_no_tag" {
		t.Errorf("expected pullpolicy_no_tag, got %s", r.Findings[0].RuleID)
	}
}

func TestPinnedTagGetsDigestWarning(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx:1.25.3")))
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding (no_digest), got %d", len(r.Findings))
	}
	if r.Findings[0].RuleID != "pullpolicy_no_digest" {
		t.Errorf("expected pullpolicy_no_digest, got %s", r.Findings[0].RuleID)
	}
	if r.Findings[0].Severity != "medium" {
		t.Errorf("expected medium, got %s", r.Findings[0].Severity)
	}
}

func TestDigestPinnedClean(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx:1.25.3@sha256:abc123def456")))
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 findings for digest-pinned image, got %d", len(r.Findings))
	}
}

func TestDigestOnlyClean(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx@sha256:abc123def456")))
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 findings for digest-only image, got %d", len(r.Findings))
	}
}

func TestVariableImageDetected(t *testing.T) {
	r := Analyze(collected(svc("app", "${IMAGE_NAME}:${VERSION}")))
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "pullpolicy_variable_image" {
			found = true
		}
	}
	if !found {
		t.Error("expected pullpolicy_variable_image finding")
	}
}

func TestVariableDollarSign(t *testing.T) {
	r := Analyze(collected(svc("app", "$MY_IMAGE")))
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "pullpolicy_variable_image" {
			found = true
		}
	}
	if !found {
		t.Error("expected pullpolicy_variable_image for $ reference")
	}
}

func TestRegistryImageLatest(t *testing.T) {
	r := Analyze(collected(svc("api", "ghcr.io/org/app:latest")))
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Findings))
	}
	if r.Findings[0].RuleID != "pullpolicy_latest_tag" {
		t.Errorf("expected pullpolicy_latest_tag, got %s", r.Findings[0].RuleID)
	}
}

func TestRegistryImagePinned(t *testing.T) {
	r := Analyze(collected(svc("api", "ghcr.io/org/app:v2.1.0")))
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding (no_digest), got %d", len(r.Findings))
	}
	if r.Findings[0].RuleID != "pullpolicy_no_digest" {
		t.Errorf("expected pullpolicy_no_digest, got %s", r.Findings[0].RuleID)
	}
}

func TestEmptyImageSkipped(t *testing.T) {
	r := Analyze(collected(compose.Service{Name: "builder"}))
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 findings for empty image, got %d", len(r.Findings))
	}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.Total != 0 {
		t.Errorf("expected 0 total, got %d", r.Summary.Total)
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(collected(
		svc("a", "nginx:latest"),
		svc("b", "python"),
		svc("c", "redis:7.0@sha256:abc"),
	))
	if r.Summary.Services != 2 {
		t.Errorf("expected 2 services affected, got %d", r.Summary.Services)
	}
}

func TestScorePerfect(t *testing.T) {
	r := Analyze(collected(svc("clean", "nginx:1.25@sha256:abc")))
	if Score(r) != 100 {
		t.Errorf("expected score 100, got %.0f", Score(r))
	}
}

func TestScoreDegrades(t *testing.T) {
	r := Analyze(collected(svc("a", "nginx:latest")))
	s := Score(r)
	if s >= 100 {
		t.Errorf("expected score < 100, got %.0f", s)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx:latest")))
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text")
	}
	if !contains(text, "Pull Policy") {
		t.Error("expected header in output")
	}
	if !contains(text, "pullpolicy_latest_tag") {
		t.Error("expected rule ID in output")
	}
}

func TestFormatTextClean(t *testing.T) {
	r := Analyze(collected(svc("clean", "nginx:1.25@sha256:abc")))
	text := FormatText(r)
	if !contains(text, "No image") {
		t.Error("expected clean message")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx:latest")))
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var r2 Report
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if len(r2.Findings) != 1 {
		t.Errorf("expected 1 finding after round-trip, got %d", len(r2.Findings))
	}
}

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		input  string
		tag    string
		digest string
	}{
		{"nginx", "", ""},
		{"nginx:latest", "latest", ""},
		{"nginx:1.25", "1.25", ""},
		{"nginx@sha256:abc", "", "sha256:abc"},
		{"nginx:1.25@sha256:abc", "1.25", "sha256:abc"},
		{"ghcr.io/org/app:v1", "v1", ""},
	}
	for _, tt := range tests {
		ref := parseImageRef(tt.input)
		if ref.Tag != tt.tag {
			t.Errorf("parseImageRef(%q).Tag = %q, want %q", tt.input, ref.Tag, tt.tag)
		}
		if ref.Digest != tt.digest {
			t.Errorf("parseImageRef(%q).Digest = %q, want %q", tt.input, ref.Digest, tt.digest)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
