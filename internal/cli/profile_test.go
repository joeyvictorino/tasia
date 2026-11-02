package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestBuildProfileEmpty(t *testing.T) {
	p := buildProfile(nil)
	if p.Score != 100 {
		t.Errorf("empty scan should score 100, got %d", p.Score)
	}
	if p.Grade != "A" {
		t.Errorf("empty scan should be grade A, got %s", p.Grade)
	}
	if p.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", p.TotalFindings)
	}
}

func TestBuildProfileWithFindings(t *testing.T) {
	findings := []rules.Finding{
		{ID: "docker_socket_mount", Severity: rules.SeverityCritical, Title: "Docker socket mounted"},
		{ID: "exposed_inference", Severity: rules.SeverityHigh, Title: "Inference API exposed"},
		{ID: "latest_image", Severity: rules.SeverityMedium, Title: "Mutable image tag"},
		{ID: "latest_image", Severity: rules.SeverityMedium, Title: "Mutable image tag"},
	}
	p := buildProfile(findings)
	if p.TotalFindings != 4 {
		t.Errorf("expected 4 findings, got %d", p.TotalFindings)
	}
	if p.BySeverity["CRITICAL"] != 1 {
		t.Errorf("expected 1 critical, got %d", p.BySeverity["CRITICAL"])
	}
	if p.BySeverity["HIGH"] != 1 {
		t.Errorf("expected 1 high, got %d", p.BySeverity["HIGH"])
	}
	if p.BySeverity["MEDIUM"] != 2 {
		t.Errorf("expected 2 medium, got %d", p.BySeverity["MEDIUM"])
	}
	// Score: 100 - 25 - 10 - 5 - 5 = 55
	if p.Score != 55 {
		t.Errorf("expected score 55, got %d", p.Score)
	}
	if p.Grade != "D" {
		t.Errorf("expected grade D, got %s", p.Grade)
	}
}

func TestScoreFloorAtZero(t *testing.T) {
	findings := make([]rules.Finding, 10)
	for i := range findings {
		findings[i] = rules.Finding{ID: "docker_socket_mount", Severity: rules.SeverityCritical, Title: "test"}
	}
	p := buildProfile(findings)
	if p.Score != 0 {
		t.Errorf("score should floor at 0, got %d", p.Score)
	}
	if p.Grade != "F" {
		t.Errorf("expected grade F, got %s", p.Grade)
	}
}

func TestTopIssuesSorted(t *testing.T) {
	findings := []rules.Finding{
		{ID: "latest_image", Severity: rules.SeverityMedium, Title: "Mutable tag"},
		{ID: "latest_image", Severity: rules.SeverityMedium, Title: "Mutable tag"},
		{ID: "latest_image", Severity: rules.SeverityMedium, Title: "Mutable tag"},
		{ID: "docker_socket_mount", Severity: rules.SeverityCritical, Title: "Socket mount"},
	}
	p := buildProfile(findings)
	if len(p.TopIssues) < 2 {
		t.Fatalf("expected at least 2 top issues, got %d", len(p.TopIssues))
	}
	if p.TopIssues[0].Severity != "CRITICAL" {
		t.Errorf("top issue should be critical, got %s", p.TopIssues[0].Severity)
	}
}

func TestCategoryFromID(t *testing.T) {
	tests := []struct{ id, want string }{
		{"exposed_inference", "compose"},
		{"docker_socket_mount", "compose"},
		{"agent_auto_approve", "agent"},
		{"kube_privileged", "kubernetes"},
		{"helm_insecure_default", "helm"},
		{"tf_sg_ingress_all", "terraform"},
		{"dockerfile_user_root", "dockerfile"},
		{"reverse_proxy_no_auth", "proxy"},
		{"unknown_rule", "other"},
	}
	for _, tt := range tests {
		got := categoryFromID(tt.id)
		if got != tt.want {
			t.Errorf("categoryFromID(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestProfileJSONOutput(t *testing.T) {
	findings := []rules.Finding{
		{ID: "exposed_inference", Severity: rules.SeverityHigh, Title: "Inference exposed"},
	}
	p := buildProfile(findings)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["score"]; !ok {
		t.Error("JSON should contain 'score' field")
	}
	if _, ok := decoded["grade"]; !ok {
		t.Error("JSON should contain 'grade' field")
	}
}

func TestProfileCLIDispatch(t *testing.T) {
	dir := t.TempDir()
	err := Run([]string{"profile", "--path", dir, "--format", "json"})
	if err != nil {
		t.Fatalf("profile command failed: %v", err)
	}
}

func TestRecommendationsEmpty(t *testing.T) {
	p := buildProfile(nil)
	if len(p.Recommendations) == 0 {
		t.Error("even clean profile should have a recommendation")
	}
	found := false
	for _, r := range p.Recommendations {
		if strings.Contains(r, "No critical") {
			found = true
		}
	}
	if !found {
		t.Error("clean profile should recommend maintaining posture")
	}
}

func TestRecommendationsCritical(t *testing.T) {
	findings := []rules.Finding{
		{ID: "docker_socket_mount", Severity: rules.SeverityCritical, Title: "test"},
	}
	p := buildProfile(findings)
	found := false
	for _, r := range p.Recommendations {
		if strings.Contains(r, "critical") {
			found = true
		}
	}
	if !found {
		t.Error("profile with critical findings should recommend fixing them")
	}
}
