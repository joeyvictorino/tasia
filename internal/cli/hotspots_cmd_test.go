package cli

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestBuildHotspotsEmpty(t *testing.T) {
	r := buildHotspots(nil, "/tmp", 10)
	if r.TotalFiles != 0 {
		t.Errorf("expected 0 files, got %d", r.TotalFiles)
	}
	if r.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.TotalFindings)
	}
}

func TestBuildHotspotsGroupsByFile(t *testing.T) {
	findings := []rules.Finding{
		{ID: "agent_runtime_privileged", Severity: "CRITICAL", File: "/app/docker-compose.yml", Line: 10, Title: "Privileged"},
		{ID: "agent_runtime_privileged", Severity: "HIGH", File: "/app/docker-compose.yml", Line: 20, Title: "Another"},
		{ID: "env_hardcoded_secret", Severity: "HIGH", File: "/app/.env", Line: 1, Title: "Secret"},
	}
	r := buildHotspots(findings, "/app", 10)
	if r.TotalFiles != 2 {
		t.Errorf("expected 2 files, got %d", r.TotalFiles)
	}
	if r.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", r.TotalFindings)
	}
	if r.Hotspots[0].FindingCount != 2 {
		t.Errorf("expected top hotspot with 2 findings, got %d", r.Hotspots[0].FindingCount)
	}
}

func TestBuildHotspotsScoring(t *testing.T) {
	findings := []rules.Finding{
		{ID: "agent_x", Severity: "CRITICAL", File: "/a/f1.yml", Line: 1},
		{ID: "env_x", Severity: "LOW", File: "/a/f2.yml", Line: 1},
	}
	r := buildHotspots(findings, "/a", 10)
	if len(r.Hotspots) != 2 {
		t.Fatalf("expected 2, got %d", len(r.Hotspots))
	}
	if r.Hotspots[0].RiskScore <= r.Hotspots[1].RiskScore {
		t.Error("CRITICAL should score higher than LOW")
	}
}

func TestBuildHotspotsTopN(t *testing.T) {
	var findings []rules.Finding
	for i := 0; i < 20; i++ {
		findings = append(findings, rules.Finding{
			ID: "agent_x", Severity: "MEDIUM", File: "/a/" + string(rune('A'+i)) + ".yml", Line: 1,
		})
	}
	r := buildHotspots(findings, "/a", 5)
	if len(r.Hotspots) != 5 {
		t.Errorf("expected 5 hotspots, got %d", len(r.Hotspots))
	}
}

func TestCategoryFromRuleID(t *testing.T) {
	tests := []struct{ input, want string }{
		{"agent_runtime_privileged", "agent"},
		{"env_hardcoded_secret", "env"},
		{"compose_network_mode", "compose"},
		{"unknownrule", "unknownrule"},
	}
	for _, tt := range tests {
		got := categoryFromRuleID(tt.input)
		if got != tt.want {
			t.Errorf("categoryFromRuleID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatHotspotsText(t *testing.T) {
	r := hotspotResult{
		TotalFiles:    2,
		TotalFindings: 5,
		Hotspots: []hotspotEntry{
			{File: "docker-compose.yml", FindingCount: 3, RiskScore: 25.0, BySeverity: map[string]int{"HIGH": 2, "MEDIUM": 1}},
		},
	}
	text := formatHotspotsText(r)
	if !strings.Contains(text, "Finding Hotspots") {
		t.Error("missing header")
	}
	if !strings.Contains(text, "docker-compose.yml") {
		t.Error("missing file")
	}
	if !strings.Contains(text, "25.0") {
		t.Error("missing score")
	}
}

func TestTruncPath(t *testing.T) {
	short := "file.yml"
	if truncPath(short, 40) != short {
		t.Error("short path should not be truncated")
	}
	long := "/very/long/path/to/some/deeply/nested/file/in/the/project/tree.yml"
	truncated := truncPath(long, 40)
	if len(truncated) > 40 {
		t.Errorf("truncated path too long: %d", len(truncated))
	}
	if !strings.HasPrefix(truncated, "...") {
		t.Error("truncated path should start with ...")
	}
}

func TestFormatSevCounts(t *testing.T) {
	m := map[string]int{"CRITICAL": 1, "LOW": 2}
	s := formatSevCounts(m)
	if !strings.Contains(s, "c:1") {
		t.Error("missing critical count")
	}
	if !strings.Contains(s, "l:2") {
		t.Error("missing low count")
	}
}
