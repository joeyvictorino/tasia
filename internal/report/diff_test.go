package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestDiffFindings_NewAndFixed(t *testing.T) {
	base := []rules.Finding{
		{ID: "T001", File: "a.yaml", Line: 1, Severity: rules.SeverityHigh, Title: "old issue"},
		{ID: "T002", File: "b.yaml", Line: 5, Severity: rules.SeverityMedium, Title: "shared"},
	}
	cur := []rules.Finding{
		{ID: "T002", File: "b.yaml", Line: 5, Severity: rules.SeverityMedium, Title: "shared"},
		{ID: "T003", File: "c.yaml", Line: 10, Severity: rules.SeverityCritical, Title: "new issue"},
	}
	d := DiffFindings(base, cur)
	if len(d.New) != 1 || d.New[0].ID != "T003" {
		t.Errorf("expected 1 new finding T003, got %d: %v", len(d.New), d.New)
	}
	if len(d.Fixed) != 1 || d.Fixed[0].ID != "T001" {
		t.Errorf("expected 1 fixed finding T001, got %d: %v", len(d.Fixed), d.Fixed)
	}
	if len(d.Unchanged) != 1 || d.Unchanged[0].ID != "T002" {
		t.Errorf("expected 1 unchanged finding T002, got %d: %v", len(d.Unchanged), d.Unchanged)
	}
}

func TestDiffFindings_Empty(t *testing.T) {
	d := DiffFindings(nil, nil)
	if len(d.New) != 0 || len(d.Fixed) != 0 || len(d.Unchanged) != 0 {
		t.Error("diff of empty sets should be empty")
	}
}

func TestDiffFindings_AllNew(t *testing.T) {
	cur := []rules.Finding{
		{ID: "T001", File: "x.yaml", Line: 1, Severity: rules.SeverityLow, Title: "first"},
	}
	d := DiffFindings(nil, cur)
	if len(d.New) != 1 {
		t.Errorf("expected 1 new, got %d", len(d.New))
	}
	if len(d.Fixed) != 0 {
		t.Error("expected 0 fixed")
	}
}

func TestDiffFindings_AllFixed(t *testing.T) {
	base := []rules.Finding{
		{ID: "T001", File: "x.yaml", Line: 1, Severity: rules.SeverityLow, Title: "gone"},
	}
	d := DiffFindings(base, nil)
	if len(d.Fixed) != 1 {
		t.Errorf("expected 1 fixed, got %d", len(d.Fixed))
	}
	if len(d.New) != 0 {
		t.Error("expected 0 new")
	}
}

func TestDiffFindings_SameIDDifferentLine(t *testing.T) {
	base := []rules.Finding{
		{ID: "T001", File: "a.yaml", Line: 1, Severity: rules.SeverityHigh, Title: "old"},
	}
	cur := []rules.Finding{
		{ID: "T001", File: "a.yaml", Line: 99, Severity: rules.SeverityHigh, Title: "moved"},
	}
	d := DiffFindings(base, cur)
	if len(d.New) != 1 || len(d.Fixed) != 1 {
		t.Errorf("same ID at different line should be new+fixed, got new=%d fixed=%d", len(d.New), len(d.Fixed))
	}
}

func TestDiffToJSON(t *testing.T) {
	d := DiffResult{
		BaseDecision:    "PASS",
		CurrentDecision: "BLOCKED",
		New: []rules.Finding{
			{ID: "T001", File: "a.yaml", Line: 1, Severity: rules.SeverityHigh, Title: "bad"},
		},
	}
	out, err := DiffToJSON(d)
	if err != nil {
		t.Fatal(err)
	}
	var parsed DiffResult
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.BaseDecision != "PASS" || parsed.CurrentDecision != "BLOCKED" {
		t.Error("decisions not preserved")
	}
	if len(parsed.New) != 1 {
		t.Error("new findings not preserved")
	}
}

func TestDiffToText(t *testing.T) {
	d := DiffResult{
		BaseDecision:    "PASS",
		CurrentDecision: "BLOCKED",
		New: []rules.Finding{
			{ID: "T001", File: "a.yaml", Line: 1, Severity: rules.SeverityHigh, Title: "bad thing"},
		},
		Fixed: []rules.Finding{
			{ID: "T002", File: "b.yaml", Line: 5, Severity: rules.SeverityLow, Title: "fixed thing"},
		},
		Unchanged: []rules.Finding{
			{ID: "T003", File: "c.yaml", Line: 10, Severity: rules.SeverityMedium, Title: "still there"},
		},
	}
	text := DiffToText(d)
	if !strings.Contains(text, "TASIA DIFF") {
		t.Error("missing header")
	}
	if !strings.Contains(text, "New findings (1)") {
		t.Error("missing new section")
	}
	if !strings.Contains(text, "+ [HIGH]") {
		t.Error("missing new finding marker")
	}
	if !strings.Contains(text, "Fixed findings (1)") {
		t.Error("missing fixed section")
	}
	if !strings.Contains(text, "- [LOW]") {
		t.Error("missing fixed finding marker")
	}
	if !strings.Contains(text, "Unchanged: 1") {
		t.Error("missing unchanged count")
	}
}
