package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/config"
	"github.com/joeyvictorino/tasia/internal/ignore"
	"github.com/joeyvictorino/tasia/internal/report"
	"github.com/joeyvictorino/tasia/internal/rules"
)

type execSummary struct {
	Path          string            `json:"path"`
	Decision      string            `json:"decision"`
	Risk          string            `json:"risk"`
	TotalFindings int               `json:"total_findings"`
	BySeverity    map[string]int    `json:"by_severity"`
	ByCategory    map[string]int    `json:"by_category"`
	TopFindings   []summaryFinding  `json:"top_findings"`
	RuleCoverage  int               `json:"rules_evaluated"`
	FilesScanned  int               `json:"files_scanned"`
}

type summaryFinding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	File     string `json:"file"`
}

func runSummaryCmd(args []string) error {
	fs := flag.NewFlagSet("summary", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	top := fs.Int("top", 5, "number of top findings to show")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	if len(collected.ParseErrors) > 0 {
		if *format == "json" {
			fmt.Println(report.ErrorJSON(collected.ParseErrors))
		} else {
			report.PrintErrorVerdict(collected.ParseErrors)
		}
		os.Exit(2)
	}

	findings := rules.Evaluate(collected)

	if pol, err := ignore.Load(absPath); err == nil {
		pol.AddInline(ignore.ScanInline(absPath))
		findings = filterFindings(findings, pol)
	}

	if cfg, err := config.Load(absPath); err == nil {
		findings = applySeverityOverrides(findings, cfg)
	}

	decision, risk := report.Decide(findings, "", false)

	bySev := make(map[string]int)
	byCat := make(map[string]int)
	for _, f := range findings {
		bySev[string(f.Severity)]++
		parts := strings.SplitN(f.ID, "_", 2)
		cat := parts[0]
		byCat[cat]++
	}

	var topFindings []summaryFinding
	count := *top
	if count > len(findings) {
		count = len(findings)
	}
	for i := 0; i < count; i++ {
		topFindings = append(topFindings, summaryFinding{
			Severity: string(findings[i].Severity),
			Title:    findings[i].Title,
			File:     findings[i].File,
		})
	}

	catalog := rules.Catalog()

	fileSet := make(map[string]bool)
	for _, f := range findings {
		fileSet[f.File] = true
	}

	summary := execSummary{
		Path:          absPath,
		Decision:      decision,
		Risk:          risk,
		TotalFindings: len(findings),
		BySeverity:    bySev,
		ByCategory:    byCat,
		TopFindings:   topFindings,
		RuleCoverage:  len(catalog),
		FilesScanned:  len(fileSet),
	}

	switch *format {
	case "json":
		out, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	default:
		fmt.Printf("TASIA Executive Summary\n")
		fmt.Printf("=======================\n\n")
		fmt.Printf("Path:     %s\n", summary.Path)
		fmt.Printf("Decision: %s\n", summary.Decision)
		fmt.Printf("Risk:     %s\n\n", summary.Risk)
		fmt.Printf("Findings: %d total across %d files\n", summary.TotalFindings, summary.FilesScanned)
		fmt.Printf("Rules:    %d evaluated\n\n", summary.RuleCoverage)

		if len(bySev) > 0 {
			fmt.Println("By Severity:")
			for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
				if c, ok := bySev[sev]; ok {
					fmt.Printf("  %-10s %d\n", sev, c)
				}
			}
			fmt.Println()
		}

		if len(topFindings) > 0 {
			fmt.Println("Top Findings:")
			for i, f := range topFindings {
				fmt.Printf("  %d. [%s] %s (%s)\n", i+1, f.Severity, f.Title, f.File)
			}
		}
	}

	return nil
}
