package sigverify

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestIsDigestPinned(t *testing.T) {
	if !isDigestPinned("nginx@sha256:abc123") {
		t.Error("expected digest-pinned image to be detected")
	}
	if isDigestPinned("nginx:latest") {
		t.Error("expected non-pinned image to not be detected")
	}
}

func TestIsLatestOrUntagged(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"nginx", true},
		{"nginx:latest", true},
		{"nginx:", true},
		{"nginx:1.21", false},
		{"", false},
	}
	for _, tc := range tests {
		got := isLatestOrUntagged(tc.image)
		if got != tc.want {
			t.Errorf("isLatestOrUntagged(%q) = %v, want %v", tc.image, got, tc.want)
		}
	}
}

func TestHasContentTrustEnabled(t *testing.T) {
	yes := []string{"DOCKER_CONTENT_TRUST=1"}
	no := []string{"DOCKER_CONTENT_TRUST=0"}
	empty := []string{}
	if !hasContentTrustEnabled(yes) {
		t.Error("expected content trust enabled")
	}
	if hasContentTrustEnabled(no) {
		t.Error("expected content trust disabled")
	}
	if hasContentTrustEnabled(empty) {
		t.Error("expected content trust disabled for empty env")
	}
}

func TestHasCosignVerification(t *testing.T) {
	yes := []string{"COSIGN_KEY=/path/to/key.pub"}
	no := []string{"MY_VAR=hello"}
	if !hasCosignVerification(yes) {
		t.Error("expected cosign verification detected")
	}
	if hasCosignVerification(no) {
		t.Error("expected no cosign verification")
	}
}

func TestHasInsecureRegistrySetting(t *testing.T) {
	yes := []string{"INSECURE_REGISTRY=true"}
	no := []string{"REGISTRY=docker.io"}
	if !hasInsecureRegistrySetting(yes) {
		t.Error("expected insecure registry detected")
	}
	if hasInsecureRegistrySetting(no) {
		t.Error("expected no insecure registry")
	}
}

func TestIsFromTrustedRegistry(t *testing.T) {
	if !isFromTrustedRegistry("docker.io/library/nginx") {
		t.Error("expected docker.io to be trusted")
	}
	if !isFromTrustedRegistry("ghcr.io/org/image") {
		t.Error("expected ghcr.io to be trusted")
	}
	if !isFromTrustedRegistry("nginx") {
		t.Error("expected plain image name to be trusted")
	}
	if isFromTrustedRegistry("evil.registry.io/image:latest") {
		t.Error("expected unknown registry to be untrusted")
	}
}

func TestAnalyzeServiceNoDigestPin(t *testing.T) {
	svc := compose.Service{Name: "web", Image: "nginx:1.21"}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "no_digest_pin" {
			found = true
		}
	}
	if !found {
		t.Error("expected no_digest_pin finding for undigested image")
	}
}

func TestAnalyzeServiceUnsignedImage(t *testing.T) {
	svc := compose.Service{Name: "web", Image: "nginx"}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "unsigned_image" {
			found = true
		}
	}
	if !found {
		t.Error("expected unsigned_image finding for untagged image")
	}
}

func TestAnalyzeServiceNoContentTrust(t *testing.T) {
	svc := compose.Service{Name: "web", Image: "nginx:1.21"}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "no_content_trust" {
			found = true
		}
	}
	if !found {
		t.Error("expected no_content_trust finding")
	}
}

func TestAnalyzeServiceInsecureRegistry(t *testing.T) {
	svc := compose.Service{
		Name:        "web",
		Image:       "nginx:1.21",
		Environment: []string{"INSECURE_REGISTRY=true"},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "insecure_registry" {
			found = true
		}
	}
	if !found {
		t.Error("expected insecure_registry finding")
	}
}

func TestAnalyzeServiceUntrustedRegistry(t *testing.T) {
	svc := compose.Service{Name: "web", Image: "evil.registry.io/image:v1"}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "missing_verify_policy" {
			found = true
		}
	}
	if !found {
		t.Error("expected missing_verify_policy finding for untrusted registry")
	}
}

func TestAnalyzeServiceDigestPinnedClean(t *testing.T) {
	svc := compose.Service{
		Name:        "web",
		Image:       "nginx@sha256:abc123def456",
		Environment: []string{"DOCKER_CONTENT_TRUST=1"},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	for _, f := range sr.Findings {
		if f.Rule == "no_digest_pin" || f.Rule == "unsigned_image" {
			t.Errorf("unexpected finding %s for digest-pinned image with content trust", f.Rule)
		}
	}
}

func TestAnalyze(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx"},
					{Name: "api", Image: "myapp@sha256:abc123", Environment: []string{"DOCKER_CONTENT_TRUST=1"}},
				},
			},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings == 0 {
		t.Error("expected findings for untagged image")
	}
}

func TestFormatText(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{
				Path:     "docker-compose.yml",
				Services: []compose.Service{{Name: "svc1", Image: "nginx"}},
			},
		},
	}
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Image Signature Verification") {
		t.Error("expected header in text output")
	}
	if !strings.Contains(text, "svc1") {
		t.Error("expected service name in text output")
	}
}

func TestSummarize(t *testing.T) {
	services := []ServiceResult{
		{
			Service: "a",
			Findings: []Finding{
				{Rule: "unsigned_image"},
				{Rule: "no_content_trust"},
			},
		},
		{
			Service: "b",
			Findings: []Finding{
				{Rule: "insecure_registry"},
			},
		},
	}
	s := summarize(services)
	if s.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", s.TotalServices)
	}
	if s.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", s.TotalFindings)
	}
	if s.UnsignedImage != 1 {
		t.Errorf("expected 1 unsigned image, got %d", s.UnsignedImage)
	}
	if s.InsecureRegistry != 1 {
		t.Errorf("expected 1 insecure registry, got %d", s.InsecureRegistry)
	}
}
