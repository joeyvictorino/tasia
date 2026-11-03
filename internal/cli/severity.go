package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/rules"
)

type SeverityReport struct {
	Counts        map[string]int     `json:"counts"`
	Percentages   map[string]float64 `json:"percentages"`
	RiskScore     int                `json:"risk_score"`
	TotalFindings int                `json:"total_findings"`
	Trend         string             `json:"trend,omitempty"`
}

func computeRiskScore(counts map[string]int) int {
	return counts["CRITICAL"]*10 + counts["HIGH"]*5 + counts["MEDIUM"]*2 + counts["LOW"]*1
}

func computePercentages(counts map[string]int, total int) map[string]float64 {
	pcts := map[string]float64{}
	if total == 0 {
		return pcts
	}
	for sev, count := range counts {
		pcts[sev] = float64(count) / float64(total) * 100.0
	}
	return pcts
}

func computeTrend(currentScore int, baselinePath string) string {
	if baselinePath == "" {
		return ""
	}
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		return ""
	}
	var snap BaselineSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return ""
	}
	baselineCounts := map[string]int{}
	for _, f := range snap.Findings {
		baselineCounts[f.Severity]++
	}
	baselineScore := computeRiskScore(baselineCounts)

	if currentScore < baselineScore {
		return "improving"
	}
	if currentScore > baselineScore {
		return "degrading"
	}
	return "stable"
}

func buildSeverityReport(findings []rules.Finding, baselinePath string) SeverityReport {
	counts := map[string]int{}
	for _, f := range findings {
		counts[string(f.Severity)]++
	}

	total := len(findings)
	pcts := computePercentages(counts, total)
	score := computeRiskScore(counts)
	trend := computeTrend(score, baselinePath)

	return SeverityReport{
		Counts:        counts,
		Percentages:   pcts,
		RiskScore:     score,
		TotalFindings: total,
		Trend:         trend,
	}
}

func runSeverity(args []string) error {
	fs := flag.NewFlagSet("severity", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	baselinePath := fs.String("baseline", "", "baseline JSON file for trend analysis")
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

	report := buildSeverityReport(findings, *baselinePath)

	switch *format {
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		fmt.Printf("Severity Distribution (%d findings)\n\n", report.TotalFindings)
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
			count := report.Counts[sev]
			pct := report.Percentages[sev]
			if count > 0 {
				fmt.Printf("  %-10s %3d  (%5.1f%%)\n", sev, count, pct)
			} else {
				fmt.Printf("  %-10s %3d  (%5.1f%%)\n", sev, 0, 0.0)
			}
		}
		fmt.Printf("\nRisk Score: %d\n", report.RiskScore)
		if report.Trend != "" {
			fmt.Printf("Trend:      %s\n", report.Trend)
		}
	}
	return nil
}
