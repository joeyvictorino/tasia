package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/rules"
)

func runStatus(args []string) error {
	fs := flag.NewFlagSet("tasia status", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	_ = recursive

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	rawFindings := rules.Evaluate(collected)
	var findings []statusFinding
	for _, f := range rawFindings {
		findings = append(findings, statusFinding{
			RuleID:   f.ID,
			Severity: strings.ToLower(string(f.Severity)),
			File:     f.File,
			Message:  f.Title,
		})
	}

	result := buildStatus(findings)

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	default:
		fmt.Print(formatStatusText(result))
		return nil
	}
}

type statusFinding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Message  string `json:"message"`
}

type statusResult struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByCategory    map[string]int `json:"by_category"`
	Grade         string         `json:"grade"`
	PassRate      float64        `json:"pass_rate"`
	TopIssues     []statusIssue  `json:"top_issues"`
}

type statusIssue struct {
	RuleID   string `json:"rule_id"`
	Count    int    `json:"count"`
	Severity string `json:"severity"`
}

func buildStatus(findings []statusFinding) statusResult {
	bySev := map[string]int{}
	byCat := map[string]int{}
	ruleCount := map[string]int{}
	ruleSev := map[string]string{}

	for _, f := range findings {
		sev := f.Severity
		if sev == "" {
			sev = "info"
		}
		bySev[sev]++

		cat := categoryFromRule(f.RuleID)
		byCat[cat]++

		ruleCount[f.RuleID]++
		ruleSev[f.RuleID] = sev
	}

	var top []statusIssue
	for rid, cnt := range ruleCount {
		top = append(top, statusIssue{RuleID: rid, Count: cnt, Severity: ruleSev[rid]})
	}
	sortIssues(top)
	if len(top) > 5 {
		top = top[:5]
	}

	grade := computeGrade(bySev)
	passRate := computePassRate(bySev)

	return statusResult{
		TotalFindings: len(findings),
		BySeverity:    bySev,
		ByCategory:    byCat,
		Grade:         grade,
		PassRate:      passRate,
		TopIssues:     top,
	}
}

func categoryFromRule(ruleID string) string {
	parts := strings.SplitN(ruleID, "_", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return "unknown"
}

func sortIssues(issues []statusIssue) {
	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	for i := 0; i < len(issues); i++ {
		for j := i + 1; j < len(issues); j++ {
			si := sevOrder[issues[i].Severity]
			sj := sevOrder[issues[j].Severity]
			if sj < si || (sj == si && issues[j].Count > issues[i].Count) {
				issues[i], issues[j] = issues[j], issues[i]
			}
		}
	}
}

func computeGrade(bySev map[string]int) string {
	crit := bySev["critical"]
	high := bySev["high"]
	med := bySev["medium"]

	if crit > 0 {
		return "F"
	}
	if high > 5 {
		return "D"
	}
	if high > 0 {
		return "C"
	}
	if med > 5 {
		return "B"
	}
	return "A"
}

func computePassRate(bySev map[string]int) float64 {
	total := 0
	blocking := 0
	for sev, cnt := range bySev {
		total += cnt
		if sev == "critical" || sev == "high" {
			blocking += cnt
		}
	}
	if total == 0 {
		return 100.0
	}
	return float64(total-blocking) / float64(total) * 100.0
}

func formatStatusText(r statusResult) string {
	var b strings.Builder
	b.WriteString("Security Posture Dashboard\n")
	b.WriteString("========================================\n\n")

	fmt.Fprintf(&b, "  Grade: %s\n", r.Grade)
	fmt.Fprintf(&b, "  Total findings: %d\n", r.TotalFindings)
	fmt.Fprintf(&b, "  Pass rate: %.1f%%\n\n", r.PassRate)

	b.WriteString("Severity breakdown:\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if cnt, ok := r.BySeverity[sev]; ok && cnt > 0 {
			bar := strings.Repeat("#", cnt)
			if len(bar) > 40 {
				bar = bar[:40] + "..."
			}
			fmt.Fprintf(&b, "  %-10s %4d  %s\n", sev, cnt, bar)
		}
	}

	if len(r.TopIssues) > 0 {
		b.WriteString("\nTop issues:\n")
		for i, iss := range r.TopIssues {
			fmt.Fprintf(&b, "  %d. [%s] %s (%d occurrences)\n",
				i+1, iss.Severity, iss.RuleID, iss.Count)
		}
	}

	b.WriteString("\n")
	return b.String()
}
