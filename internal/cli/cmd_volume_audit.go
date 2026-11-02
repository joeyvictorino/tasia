package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/volumeaudit"
)

func runVolumeAudit(args []string) error {
	fs := flag.NewFlagSet("volume-audit", flag.ContinueOnError)
	path := fs.String("path", ".", "Path to scan")
	format := fs.String("format", "text", "Output format: text or json")
	recursive := fs.Bool("recursive", false, "Scan directories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	if *recursive {
		return runVolumeAuditRecursive(absPath, *format)
	}

	c, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return fmt.Errorf("collect: %w", err)
	}
	r := volumeaudit.Analyze(c)
	return printVolumeAuditResult(r, *format)
}

func runVolumeAuditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := volumeaudit.Analyze(c)
		if err := printVolumeAuditResult(r, format); err != nil {
			return err
		}
	}
	return nil
}

func printVolumeAuditResult(r volumeaudit.Report, format string) error {
	switch format {
	case "json":
		fmt.Println(volumeaudit.FormatJSON(r))
	default:
		fmt.Print(volumeaudit.FormatText(r))
	}
	if r.Summary.FindingCount > 0 {
		os.Exit(1)
	}
	return nil
}
