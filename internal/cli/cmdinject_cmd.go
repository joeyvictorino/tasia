package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/cmdinject"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runCmdinject(args []string) error {
	fs := flag.NewFlagSet("cmdinject", flag.ContinueOnError)
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
		return runCmdinjectRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := cmdinject.Analyze(collected)
	return printCmdinjectResult(r, *format)
}

func runCmdinjectRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := cmdinject.Analyze(collected)
		if r.Summary.TotalFindings > 0 {
			if err := printCmdinjectResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printCmdinjectResult(r cmdinject.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(cmdinject.FormatText(r))
	}
	return nil
}
