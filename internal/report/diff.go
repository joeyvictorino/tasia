package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/rules"
)

// DiffResult holds the delta between two scans.
type DiffResult struct {
	BaseDecision    string `json:"base_decision"`
	CurrentDecision string `json:"current_decision"`
	New             []rules.Finding `json:"new"`
	Fixed           []rules.Finding `json:"fixed"`
	Unchanged       []rules.Finding `json:"unchanged"`
}

// DiffFindings compares two sets of findings. Identity is (ID, File, Line).
func DiffFindings(base, current []rules.Finding) DiffResult {
	baseSet := findingSet(base)
	curSet := findingSet(current)

	var newF, fixed, unchanged []rules.Finding

	for key, f := range curSet {
		if _, ok := baseSet[key]; ok {
			unchanged = append(unchanged, f)
		} else {
			newF = append(newF, f)
		}
	}
	for key, f := range baseSet {
		if _, ok := curSet[key]; !ok {
			fixed = append(fixed, f)
		}
	}

	return DiffResult{
		New:       newF,
		Fixed:     fixed,
		Unchanged: unchanged,
	}
}

func findingSet(findings []rules.Finding) map[string]rules.Finding {
	m := make(map[string]rules.Finding, len(findings))
	for _, f := range findings {
		key := fmt.Sprintf("%s:%s:%d", f.ID, f.File, f.Line)
		m[key] = f
	}
	return m
}

// DiffToJSON serializes a DiffResult to indented JSON.
func DiffToJSON(d DiffResult) (string, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DiffToText renders a human-readable diff summary.
func DiffToText(d DiffResult) string {
	var sb strings.Builder
	sb.WriteString("TASIA DIFF\n\n")
	sb.WriteString(fmt.Sprintf("Base: %s → Current: %s\n\n", d.BaseDecision, d.CurrentDecision))

	if len(d.New) > 0 {
		sb.WriteString(fmt.Sprintf("New findings (%d):\n", len(d.New)))
		for _, f := range d.New {
			sb.WriteString(fmt.Sprintf("  + [%s] %s:%d %s\n", f.Severity, f.File, f.Line, f.Title))
		}
		sb.WriteString("\n")
	}

	if len(d.Fixed) > 0 {
		sb.WriteString(fmt.Sprintf("Fixed findings (%d):\n", len(d.Fixed)))
		for _, f := range d.Fixed {
			sb.WriteString(fmt.Sprintf("  - [%s] %s:%d %s\n", f.Severity, f.File, f.Line, f.Title))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("Unchanged: %d  |  New: %d  |  Fixed: %d\n", len(d.Unchanged), len(d.New), len(d.Fixed)))
	return sb.String()
}
