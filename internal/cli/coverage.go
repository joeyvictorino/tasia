package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"path/filepath"
	"sort"

	"github.com/joeyvictorino/tasia/internal/rules"
)

type coverageRuleEntry struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Fired    bool   `json:"fired"`
	Count    int    `json:"count"`
}

type coverageResult struct {
	Path        string              `json:"path"`
	TotalRules  int                 `json:"total_rules"`
	FiredCount  int                 `json:"fired_count"`
	NotFired    int                 `json:"not_fired_count"`
	CoveragePct float64            `json:"coverage_pct"`
	Rules       []coverageRuleEntry `json:"rules"`
}

func buildCoverageResult(absPath string, findings []rules.Finding) coverageResult {
	catalog := rules.Catalog()

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.ID]++
	}

	var entries []coverageRuleEntry
	fired := 0
	for _, r := range catalog {
		c := counts[r.ID]
		f := c > 0
		if f {
			fired++
		}
		entries = append(entries, coverageRuleEntry{
			RuleID:   r.ID,
			Severity: string(r.Default),
			Fired:    f,
			Count:    c,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Fired != entries[j].Fired {
			return entries[i].Fired
		}
		return entries[i].RuleID < entries[j].RuleID
	})

	total := len(catalog)
	pct := 0.0
	if total > 0 {
		pct = math.Round(float64(fired)/float64(total)*1000) / 10
	}

	return coverageResult{
		Path:        absPath,
		TotalRules:  total,
		FiredCount:  fired,
		NotFired:    total - fired,
		CoveragePct: pct,
		Rules:       entries,
	}
}

func printCoverageText(r coverageResult) {
	fmt.Printf("Rule Coverage (%d/%d rules fired, %.1f%%)\n\n", r.FiredCount, r.TotalRules, r.CoveragePct)
	fmt.Printf("  %-40s %-10s %-6s %s\n", "RULE", "SEVERITY", "FIRED", "COUNT")
	fmt.Printf("  %-40s %-10s %-6s %s\n", "----", "--------", "-----", "-----")
	for _, e := range r.Rules {
		firedStr := "no"
		if e.Fired {
			firedStr = "yes"
		}
		fmt.Printf("  %-40s %-10s %-6s %d\n", e.RuleID, e.Severity, firedStr, e.Count)
	}
}

func runCoverage(args []string) error {
	fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var findings []rules.Finding
	if *recursive {
		findings = scanRecursive(absPath)
	} else {
		findings = scanDir(absPath)
	}

	result := buildCoverageResult(absPath, findings)

	switch *format {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		printCoverageText(result)
	}
	return nil
}
