package composelint

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestLintNoImage(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web"},
				},
			},
		},
	}

	r := Analyze(collected)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "lint_no_image" {
			found = true
		}
	}
	if !found {
		t.Error("expected lint_no_image finding for service without image")
	}
}

func TestLintLatestTag(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx:latest"},
				},
			},
		},
	}

	r := Analyze(collected)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "lint_latest_tag" {
			found = true
		}
	}
	if !found {
		t.Error("expected lint_latest_tag finding for :latest image")
	}
}

func TestLintNoTag(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx"},
				},
			},
		},
	}

	r := Analyze(collected)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "lint_no_tag" {
			found = true
		}
	}
	if !found {
		t.Error("expected lint_no_tag finding for image without tag")
	}
}

func TestLintPinnedDigest(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx@sha256:abc123"},
				},
			},
		},
	}

	r := Analyze(collected)
	for _, f := range r.Findings {
		if f.RuleID == "lint_latest_tag" || f.RuleID == "lint_no_tag" {
			t.Error("pinned digest should not trigger tag warnings")
		}
	}
}

func TestLintNoHealthcheck(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx:1.25"},
				},
			},
		},
	}

	r := Analyze(collected)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "lint_no_healthcheck" {
			found = true
		}
	}
	if !found {
		t.Error("expected lint_no_healthcheck finding")
	}
}

func TestLintNoRestartPolicy(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx:1.25"},
				},
			},
		},
	}

	r := Analyze(collected)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "lint_no_restart_policy" {
			found = true
		}
	}
	if !found {
		t.Error("expected lint_no_restart_policy finding")
	}
}

func TestLintNoMemLimit(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx:1.25"},
				},
			},
		},
	}

	r := Analyze(collected)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "lint_no_mem_limit" {
			found = true
		}
	}
	if !found {
		t.Error("expected lint_no_mem_limit finding")
	}
}

func TestLintWellConfiguredService(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:        "web",
						Image:       "nginx:1.25-alpine",
						MemLimit:    "512m",
						Restart:     "unless-stopped",
						Healthcheck: &compose.Healthcheck{Test: []string{"CMD", "curl", "-f", "http://localhost"}},
					},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("well-configured service should have 0 findings, got %d", r.Summary.TotalFindings)
		for _, f := range r.Findings {
			t.Logf("  unexpected: %s (%s)", f.RuleID, f.Message)
		}
	}
}

func TestLintNoServices(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml"},
		},
	}

	r := Analyze(collected)
	found := false
	for _, f := range r.Findings {
		if f.RuleID == "lint_no_services" {
			found = true
		}
	}
	if !found {
		t.Error("expected lint_no_services finding for empty compose file")
	}
}

func TestLintSummary(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web"},
					{Name: "db", Image: "postgres:16"},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Summary.TotalFiles != 1 {
		t.Errorf("total files = %d, want 1", r.Summary.TotalFiles)
	}
	if r.Summary.TotalServices != 2 {
		t.Errorf("total services = %d, want 2", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings == 0 {
		t.Error("expected at least some findings")
	}
	if r.Summary.Errors+r.Summary.Warnings+r.Summary.Info != r.Summary.TotalFindings {
		t.Error("severity counts should sum to total findings")
	}
}

func TestImageTag(t *testing.T) {
	tests := []struct {
		image string
		want  string
	}{
		{"nginx", ""},
		{"nginx:latest", "latest"},
		{"nginx:1.25", "1.25"},
		{"nginx:1.25-alpine", "1.25-alpine"},
		{"nginx@sha256:abc", "pinned-digest"},
		{"registry.example.com/app:v2", "v2"},
	}
	for _, tt := range tests {
		got := imageTag(tt.image)
		if got != tt.want {
			t.Errorf("imageTag(%q) = %q, want %q", tt.image, got, tt.want)
		}
	}
}

func TestFormatText(t *testing.T) {
	r := LintReport{
		Findings: []LintFinding{
			{File: "compose.yml", Service: "web", RuleID: "lint_no_tag", Severity: "warning", Message: "no tag", Suggestion: "add tag"},
		},
		Summary: LintSummary{TotalFiles: 1, TotalServices: 1, TotalFindings: 1, Warnings: 1},
	}

	text := FormatText(r)
	if !strings.Contains(text, "Compose Lint") {
		t.Error("output should contain header")
	}
	if !strings.Contains(text, "lint_no_tag") {
		t.Error("output should contain rule ID")
	}
	if !strings.Contains(text, "add tag") {
		t.Error("output should contain suggestion")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := LintReport{Summary: LintSummary{TotalFiles: 1}}
	text := FormatText(r)
	if !strings.Contains(text, "0 findings") {
		t.Error("empty report should show 0 findings")
	}
}
