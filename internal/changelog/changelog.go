package changelog

import (
	"fmt"
	"strings"
	"time"

	"github.com/joeyvictorino/tasia/internal/snapshot"
)

type ChangeEntry struct {
	Type     string `json:"type"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Message  string `json:"message"`
}

type Changelog struct {
	FromSnapshot string        `json:"from_snapshot"`
	ToSnapshot   string        `json:"to_snapshot"`
	Timestamp    string        `json:"timestamp"`
	NewFindings  []ChangeEntry `json:"new_findings"`
	Resolved     []ChangeEntry `json:"resolved"`
	Changes      []ChangeEntry `json:"changes"`
	Summary      string        `json:"summary"`
}

func GenerateChangelog(basePath, currentPath string) (Changelog, error) {
	base, err := snapshot.LoadSnapshot(basePath)
	if err != nil {
		return Changelog{}, fmt.Errorf("loading base snapshot: %w", err)
	}
	current, err := snapshot.LoadSnapshot(currentPath)
	if err != nil {
		return Changelog{}, fmt.Errorf("loading current snapshot: %w", err)
	}

	drift := snapshot.ComputeDrift(base, current)

	cl := Changelog{
		FromSnapshot: base.Checksum,
		ToSnapshot:   current.Checksum,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}

	for _, f := range drift.NewFindings {
		cl.NewFindings = append(cl.NewFindings, ChangeEntry{
			Type:     "new_finding",
			RuleID:   f.RuleID,
			Severity: f.Severity,
			File:     f.File,
			Message:  f.Message,
		})
	}

	for _, f := range drift.Resolved {
		cl.Resolved = append(cl.Resolved, ChangeEntry{
			Type:     "resolved",
			RuleID:   f.RuleID,
			Severity: f.Severity,
			File:     f.File,
			Message:  f.Message,
		})
	}

	baseByRule := map[string]string{}
	for _, f := range base.Findings {
		baseByRule[f.Hash] = f.Severity
	}
	for _, f := range current.Findings {
		if oldSev, ok := baseByRule[f.Hash]; ok && oldSev != f.Severity {
			cl.Changes = append(cl.Changes, ChangeEntry{
				Type:     "severity_change",
				RuleID:   f.RuleID,
				Severity: f.Severity,
				File:     f.File,
				Message:  fmt.Sprintf("severity changed from %s to %s", oldSev, f.Severity),
			})
		}
	}

	parts := []string{}
	if len(cl.NewFindings) > 0 {
		parts = append(parts, fmt.Sprintf("%d new finding(s)", len(cl.NewFindings)))
	}
	if len(cl.Resolved) > 0 {
		parts = append(parts, fmt.Sprintf("%d resolved", len(cl.Resolved)))
	}
	if len(cl.Changes) > 0 {
		parts = append(parts, fmt.Sprintf("%d changed", len(cl.Changes)))
	}
	if len(parts) == 0 {
		cl.Summary = "No changes detected."
	} else {
		cl.Summary = strings.Join(parts, ", ")
	}

	return cl, nil
}

func FormatMarkdown(c Changelog) string {
	var b strings.Builder

	b.WriteString("# Security Changelog\n\n")
	fmt.Fprintf(&b, "**Generated:** %s  \n", c.Timestamp)
	fmt.Fprintf(&b, "**From:** `%s` → **To:** `%s`  \n\n", short(c.FromSnapshot), short(c.ToSnapshot))
	fmt.Fprintf(&b, "**Summary:** %s\n\n", c.Summary)

	if len(c.NewFindings) > 0 {
		b.WriteString("## New Findings\n\n")
		for _, e := range c.NewFindings {
			fmt.Fprintf(&b, "- **[%s]** `%s` in `%s` — %s\n", e.Severity, e.RuleID, e.File, e.Message)
		}
		b.WriteString("\n")
	}

	if len(c.Resolved) > 0 {
		b.WriteString("## Resolved\n\n")
		for _, e := range c.Resolved {
			fmt.Fprintf(&b, "- ~~[%s] `%s` in `%s` — %s~~\n", e.Severity, e.RuleID, e.File, e.Message)
		}
		b.WriteString("\n")
	}

	if len(c.Changes) > 0 {
		b.WriteString("## Changes\n\n")
		for _, e := range c.Changes {
			fmt.Fprintf(&b, "- **[%s]** `%s` in `%s` — %s\n", e.Severity, e.RuleID, e.File, e.Message)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func FormatText(c Changelog) string {
	var b strings.Builder

	b.WriteString("Security Changelog\n")
	b.WriteString("========================================\n")
	fmt.Fprintf(&b, "From: %s  To: %s\n", short(c.FromSnapshot), short(c.ToSnapshot))
	fmt.Fprintf(&b, "Summary: %s\n\n", c.Summary)

	if len(c.NewFindings) > 0 {
		fmt.Fprintf(&b, "New Findings (%d):\n", len(c.NewFindings))
		for _, e := range c.NewFindings {
			fmt.Fprintf(&b, "  + [%s] %s in %s: %s\n", e.Severity, e.RuleID, e.File, e.Message)
		}
		b.WriteString("\n")
	}

	if len(c.Resolved) > 0 {
		fmt.Fprintf(&b, "Resolved (%d):\n", len(c.Resolved))
		for _, e := range c.Resolved {
			fmt.Fprintf(&b, "  - [%s] %s in %s: %s\n", e.Severity, e.RuleID, e.File, e.Message)
		}
		b.WriteString("\n")
	}

	if len(c.Changes) > 0 {
		fmt.Fprintf(&b, "Changes (%d):\n", len(c.Changes))
		for _, e := range c.Changes {
			fmt.Fprintf(&b, "  ~ [%s] %s in %s: %s\n", e.Severity, e.RuleID, e.File, e.Message)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func short(checksum string) string {
	if len(checksum) > 12 {
		return checksum[:12]
	}
	return checksum
}
