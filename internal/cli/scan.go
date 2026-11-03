package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/config"
	"github.com/joeyvictorino/tasia/internal/ignore"
	"github.com/joeyvictorino/tasia/internal/report"
	"github.com/joeyvictorino/tasia/internal/rules"
)

func runScanCmd(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	files := fs.String("files", "", "comma-separated specific files to scan")
	ruleFilter := fs.String("rules", "", "comma-separated rule IDs to check")
	format := fs.String("format", "text", "output format: text or json")
	failOn := fs.String("fail-on", "", "fail level: critical, high, medium, low")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateFailOn(*failOn); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	t0 := time.Now()

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

	if *files != "" {
		fileSet := make(map[string]bool)
		for _, f := range strings.Split(*files, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				af, err := filepath.Abs(f)
				if err == nil {
					fileSet[af] = true
				}
				fileSet[f] = true
			}
		}
		var filtered []rules.Finding
		for _, f := range findings {
			relFile := f.File
			absFile := filepath.Join(absPath, relFile)
			if fileSet[relFile] || fileSet[absFile] || fileSet[filepath.Base(relFile)] {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	if *ruleFilter != "" {
		ruleSet := make(map[string]bool)
		for _, r := range strings.Split(*ruleFilter, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				ruleSet[r] = true
			}
		}
		var filtered []rules.Finding
		for _, f := range findings {
			if ruleSet[f.ID] {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	durationMs := time.Since(t0).Milliseconds()
	decision, risk := report.Decide(findings, *failOn, false)

	switch *format {
	case "json":
		out, err := report.FindingsToJSON(findings, decision, risk, nil)
		if err != nil {
			return err
		}
		fmt.Println(out)
	default:
		report.PrintSummary(findings, decision, risk)
		fmt.Printf("\nScan completed in %dms (%d findings)\n", durationMs, len(findings))
	}

	if decision == "BLOCK" {
		os.Exit(1)
	}
	return nil
}
