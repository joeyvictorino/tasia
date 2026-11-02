package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/rules"
)

type prioritizedFinding struct {
	RuleID       string  `json:"rule_id"`
	Severity     string  `json:"severity"`
	File         string  `json:"file"`
	Line         int     `json:"line"`
	Title        string  `json:"title"`
	Category     string  `json:"category"`
	PriorityRank int     `json:"priority_rank"`
	RiskScore    float64 `json:"risk_score"`
	Factors      string  `json:"factors"`
}

type prioritizeResult struct {
	TotalFindings    int                  `json:"total_findings"`
	PrioritizedCount int                  `json:"prioritized_count"`
	Findings         []prioritizedFinding `json:"findings"`
}

var prioritySeverityWeight = map[string]float64{
	"CRITICAL": 40.0,
	"HIGH":     25.0,
	"MEDIUM":   10.0,
	"LOW":      3.0,
}

var categoryExposureWeight = map[string]float64{
	"agent":       3.0,
	"compose":     2.0,
	"docker":      2.0,
	"env":         2.5,
	"helm":        2.0,
	"k8s":         2.5,
	"network":     3.0,
	"terraform":   2.0,
	"proxy":       1.5,
	"datastore":   2.0,
}

func runPrioritize(args []string) error {
	fs := flag.NewFlagSet("prioritize", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	top := fs.Int("top", 20, "maximum findings to show")
	minScore := fs.Float64("min-score", 0, "minimum risk score to include")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return fmt.Errorf("collecting: %w", err)
	}

	rawFindings := rules.Evaluate(collected)
	result := buildPrioritized(rawFindings, absPath, *top, *minScore)

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	default:
		fmt.Print(formatPrioritizeText(result))
		return nil
	}
}

func buildPrioritized(findings []rules.Finding, basePath string, top int, minScore float64) prioritizeResult {
	fileCounts := map[string]int{}
	for _, f := range findings {
		fileCounts[f.File]++
	}

	var entries []prioritizedFinding
	for _, f := range findings {
		rel := f.File
		if strings.HasPrefix(rel, basePath) {
			rel, _ = filepath.Rel(basePath, rel)
		}

		sev := strings.ToUpper(string(f.Severity))
		cat := categoryFromRuleID(f.ID)

		sevWeight := prioritySeverityWeight[sev]
		if sevWeight == 0 {
			sevWeight = 3.0
		}

		expWeight := categoryExposureWeight[cat]
		if expWeight == 0 {
			expWeight = 1.0
		}

		density := float64(fileCounts[f.File])
		densityFactor := 1.0
		if density > 3 {
			densityFactor = 1.5
		} else if density > 1 {
			densityFactor = 1.2
		}

		score := sevWeight * expWeight * densityFactor

		if minScore > 0 && score < minScore {
			continue
		}

		var factors []string
		factors = append(factors, fmt.Sprintf("sev=%.0f", sevWeight))
		factors = append(factors, fmt.Sprintf("exp=%.1f", expWeight))
		if densityFactor > 1.0 {
			factors = append(factors, fmt.Sprintf("density=%.1f", densityFactor))
		}

		entries = append(entries, prioritizedFinding{
			RuleID:    f.ID,
			Severity:  sev,
			File:      rel,
			Line:      f.Line,
			Title:     f.Title,
			Category:  cat,
			RiskScore: score,
			Factors:   strings.Join(factors, ", "),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].RiskScore > entries[j].RiskScore
	})

	if top > 0 && len(entries) > top {
		entries = entries[:top]
	}

	for i := range entries {
		entries[i].PriorityRank = i + 1
	}

	return prioritizeResult{
		TotalFindings:    len(findings),
		PrioritizedCount: len(entries),
		Findings:         entries,
	}
}

func formatPrioritizeText(r prioritizeResult) string {
	var b strings.Builder
	b.WriteString("Risk-Based Finding Prioritization\n")
	b.WriteString("========================================\n")
	fmt.Fprintf(&b, "Total findings: %d\n", r.TotalFindings)
	fmt.Fprintf(&b, "Showing: %d (by risk score)\n\n", r.PrioritizedCount)

	if len(r.Findings) > 0 {
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "  #%d  [%s] %s\n", f.PriorityRank, f.Severity, f.RuleID)
			fmt.Fprintf(&b, "       %s:%d\n", f.File, f.Line)
			fmt.Fprintf(&b, "       Score: %.1f  (%s)\n", f.RiskScore, f.Factors)
			if f.Title != "" {
				fmt.Fprintf(&b, "       %s\n", f.Title)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}
