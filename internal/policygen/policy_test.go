package policygen

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestGeneratePolicyEmpty(t *testing.T) {
	doc := GeneratePolicy("Test Policy", "/tmp/test", nil)
	if doc.Title != "Test Policy" {
		t.Errorf("title = %q, want %q", doc.Title, "Test Policy")
	}
	if doc.Summary.NonCompliant != 0 {
		t.Errorf("non-compliant = %d, want 0", doc.Summary.NonCompliant)
	}
	if doc.Summary.ScorePct != 100 {
		t.Errorf("score = %.1f, want 100.0", doc.Summary.ScorePct)
	}
	for _, sec := range doc.Sections {
		if sec.Status != "compliant" {
			t.Errorf("section %q status = %q, want compliant", sec.Title, sec.Status)
		}
	}
}

func TestGeneratePolicyWithFindings(t *testing.T) {
	findings := []rules.Finding{
		{ID: "privileged_container", Severity: "CRITICAL", File: "docker-compose.yml", Line: 10},
		{ID: "env_hardcoded_secret", Severity: "HIGH", File: ".env", Line: 3},
	}
	doc := GeneratePolicy("Test", "/tmp", findings)

	if doc.Summary.NonCompliant < 2 {
		t.Errorf("non-compliant = %d, want >= 2", doc.Summary.NonCompliant)
	}
	if doc.Summary.ScorePct >= 100 {
		t.Errorf("score should be < 100 with findings, got %.1f", doc.Summary.ScorePct)
	}
}

func TestSectionStatuses(t *testing.T) {
	findings := []rules.Finding{
		{ID: "privileged_container", Severity: "CRITICAL", File: "compose.yml", Line: 5},
	}
	doc := GeneratePolicy("Test", "/tmp", findings)

	for _, sec := range doc.Sections {
		if sec.Title == "Container Security" {
			if sec.Status == "compliant" {
				t.Error("Container Security should not be compliant with privileged_container finding")
			}
		}
		if sec.Title == "Agent Runtime Safety" && sec.Status != "compliant" {
			t.Errorf("Agent Runtime Safety should be compliant, got %q", sec.Status)
		}
	}
}

func TestRequirementEvidence(t *testing.T) {
	findings := []rules.Finding{
		{ID: "docker_socket_mount", Severity: "CRITICAL", File: "compose.yml", Line: 12},
		{ID: "docker_socket_mount", Severity: "CRITICAL", File: "other.yml", Line: 5},
	}
	doc := GeneratePolicy("Test", "/tmp", findings)

	for _, sec := range doc.Sections {
		for _, req := range sec.Requirements {
			if req.ID == "docker_socket_mount" {
				if req.Status != "non_compliant" {
					t.Errorf("docker_socket_mount status = %q, want non_compliant", req.Status)
				}
				if !strings.Contains(req.Evidence, "2 finding(s)") {
					t.Errorf("evidence should mention 2 findings: %q", req.Evidence)
				}
			}
		}
	}
}

func TestFormatMarkdown(t *testing.T) {
	doc := GeneratePolicy("Security Policy", "/app", nil)
	md := FormatMarkdown(doc)
	if !strings.Contains(md, "# Security Policy") {
		t.Error("markdown should contain title")
	}
	if !strings.Contains(md, "PASS") {
		t.Error("markdown should contain PASS badge for compliant sections")
	}
}

func TestFormatText(t *testing.T) {
	findings := []rules.Finding{
		{ID: "agent_auto_approve", Severity: "HIGH", File: "compose.yml", Line: 7},
	}
	doc := GeneratePolicy("Policy", "/app", findings)
	txt := FormatText(doc)
	if !strings.Contains(txt, "Policy") {
		t.Error("text should contain title")
	}
	if !strings.Contains(txt, "-") {
		t.Error("text should contain - for non-compliant items")
	}
}

func TestJSONRoundtrip(t *testing.T) {
	doc := GeneratePolicy("RT", "/tmp", nil)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var doc2 PolicyDocument
	if err := json.Unmarshal(data, &doc2); err != nil {
		t.Fatal(err)
	}
	if doc2.Title != "RT" {
		t.Errorf("title = %q, want %q", doc2.Title, "RT")
	}
	if doc2.Summary.TotalRequirements != doc.Summary.TotalRequirements {
		t.Errorf("requirements mismatch after roundtrip")
	}
}

func TestSectionTitles(t *testing.T) {
	titles := SectionTitles()
	if len(titles) != 7 {
		t.Errorf("expected 7 section titles, got %d", len(titles))
	}
}
