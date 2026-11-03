package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/ulimits"
)

func runUlimits(args []string) error {
	fs := flag.NewFlagSet("ulimits", flag.ContinueOnError)
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
		return runUlimitsRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := ulimits.Analyze(collected)
	return printUlimitsResult(r, *format)
}

func runUlimitsRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := ulimits.Analyze(collected)
		if r.Summary.TotalServices > 0 {
			if err := printUlimitsResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printUlimitsResult(r ulimits.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(ulimits.FormatText(r))
	}
	return nil
}
