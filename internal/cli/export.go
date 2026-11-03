package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/report"
	"github.com/joeyvictorino/tasia/internal/rules"
)

func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "csv", "output format: csv, markdown, or junit")
	output := fs.String("output", "-", "output file (default stdout)")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var findings = scanForExport(absPath, *recursive)

	w := os.Stdout
	if *output != "-" {
		if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
			return err
		}
		f, err := os.Create(*output)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	switch *format {
	case "csv":
		if err := report.ExportCSV(findings, w); err != nil {
			return fmt.Errorf("export csv: %w", err)
		}
	case "markdown", "md":
		if err := report.ExportMarkdown(findings, w); err != nil {
			return fmt.Errorf("export markdown: %w", err)
		}
	case "junit", "junit-xml":
		if err := report.ExportJUnit(findings, w); err != nil {
			return fmt.Errorf("export junit: %w", err)
		}
	default:
		return fmt.Errorf("unknown export format %q (want csv, markdown, or junit)", *format)
	}

	if *output != "-" {
		fmt.Fprintf(os.Stderr, "tasia export: wrote %s (%s format, %d findings)\n", *output, *format, len(findings))
	}
	return nil
}

func scanForExport(absPath string, recursive bool) []rules.Finding {
	if recursive {
		return scanRecursive(absPath)
	}
	return scanDir(absPath)
}
