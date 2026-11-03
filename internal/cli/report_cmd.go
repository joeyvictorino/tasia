package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/config"
	"github.com/joeyvictorino/tasia/internal/ignore"
	"github.com/joeyvictorino/tasia/internal/report"
	"github.com/joeyvictorino/tasia/internal/rules"
)

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	path := fs.String("path", ".", "directory to scan")
	output := fs.String("output", "tasia-report.html", "output file path")
	title := fs.String("title", "", "report title (default: Tasia Security Report)")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	t0 := time.Now()

	var findings []rules.Finding
	var filesScanned int
	if *recursive {
		findings = scanRecursive(absPath)
	} else {
		collected, err := collect.WalkAndCollect(absPath)
		if err != nil {
			return err
		}
		if len(collected.ParseErrors) > 0 {
			return fmt.Errorf("could not parse %d config file(s); fix them first", len(collected.ParseErrors))
		}
		findings = rules.Evaluate(collected)
		filesScanned = collected.FilesScanned()

		if pol, err := ignore.Load(absPath); err == nil {
			pol.AddInline(ignore.ScanInline(absPath))
			findings = filterFindings(findings, pol)
		}
		if cfg, err := config.Load(absPath); err == nil {
			findings = applySeverityOverrides(findings, cfg)
		}
	}

	durationMs := time.Since(t0).Milliseconds()
	summary := report.BuildSummary(findings, filesScanned, durationMs)

	html := report.RenderHTML(findings, summary, absPath, *title)

	outPath, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, []byte(html), 0o644); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Wrote HTML report to %s (%d findings)\n", outPath, len(findings))
	return nil
}
