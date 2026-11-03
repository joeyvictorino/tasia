package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/composelint"
)

func runComposeLint(args []string) error {
	fs := flag.NewFlagSet("compose-lint", flag.ContinueOnError)
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
		return runComposeLintRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := composelint.Analyze(collected)
	return printComposeLintResult(r, *format)
}

func runComposeLintRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := composelint.Analyze(collected)
		if r.Summary.TotalServices > 0 {
			if err := printComposeLintResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printComposeLintResult(r composelint.LintReport, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(composelint.FormatText(r))
	}
	return nil
}
