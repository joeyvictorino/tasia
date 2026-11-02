package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/resourcelimits"
)

func runResourceLimits(args []string) error {
	fs := flag.NewFlagSet("resource-limits", flag.ContinueOnError)
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

	if *recursive {
		return runResourceLimitsRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := resourcelimits.Analyze(collected)
	return printResourceLimitsResult(r, *format)
}

func runResourceLimitsRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := resourcelimits.Analyze(collected)
		if r.Summary.TotalServices > 0 {
			if err := printResourceLimitsResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printResourceLimitsResult(r resourcelimits.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(resourcelimits.FormatText(r))
	}
	return nil
}
