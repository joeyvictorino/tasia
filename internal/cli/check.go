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

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	failOn := fs.String("fail-on", "low", "fail level: critical, high, medium, low")
	format := fs.String("format", "text", "output format: text or json")
	baselinePath := fs.String("baseline", "", "SARIF file of known findings to suppress")
	recursive := fs.Bool("recursive", false, "scan nested directories in monorepos")
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

	var findings []rules.Finding
	if *recursive {
		findings = scanRecursive(absPath)
	} else {
		collected, err := collect.WalkAndCollect(absPath)
		if err != nil {
			return err
		}
		if len(collected.ParseErrors) > 0 {
			if *format == "json" {
				out, _ := json.Marshal(map[string]any{
					"pass":  false,
					"error": "unparseable config",
					"total": 0,
				})
				fmt.Println(string(out))
			} else {
				fmt.Println("ERROR: unparseable config — failing closed")
			}
			os.Exit(2)
		}
		findings = rules.Evaluate(collected)
		if pol, err := ignore.Load(absPath); err == nil {
			pol.AddInline(ignore.ScanInline(absPath))
			findings = filterFindings(findings, pol)
		}
		if cfg, err := config.Load(absPath); err == nil {
			findings = applySeverityOverrides(findings, cfg)
		}
	}

	if *baselinePath != "" {
		bl, err := report.LoadBaseline(*baselinePath)
		if err != nil {
			return fmt.Errorf("loading baseline: %w", err)
		}
		findings, _ = report.FilterBaseline(findings, bl)
	}

	decision, _ := report.Decide(findings, *failOn, false)

	counts := map[string]int{}
	for _, f := range findings {
		counts[strings.ToLower(string(f.Severity))]++
	}

	pass := decision == "PASS"

	if *format == "json" {
		out, _ := json.Marshal(map[string]any{
			"pass":        pass,
			"total":       len(findings),
			"by_severity": counts,
		})
		fmt.Println(string(out))
	} else {
		if pass {
			fmt.Printf("PASS: %d findings\n", len(findings))
		} else {
			parts := []string{}
			for _, sev := range []string{"critical", "high", "medium", "low"} {
				if n, ok := counts[sev]; ok && n > 0 {
					parts = append(parts, fmt.Sprintf("%d %s", n, sev))
				}
			}
			fmt.Printf("FAIL: %d findings (%s)\n", len(findings), strings.Join(parts, ", "))
		}
	}

	if !pass {
		os.Exit(1)
	}
	return nil
}
