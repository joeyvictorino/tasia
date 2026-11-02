package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/multistage"
)

func runMultistage(args []string) error {
	fs := flag.NewFlagSet("multi-stage", flag.ContinueOnError)
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
		return runMultistageRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := multistage.Analyze(collected)
	return printMultistageResult(r, *format)
}

func runMultistageRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := multistage.Analyze(collected)
		if r.Summary.TotalFiles > 0 {
			if err := printMultistageResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printMultistageResult(r multistage.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(multistage.FormatText(r))
	}
	return nil
}
