package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/readonlyroot"
)

func runReadOnlyRoot(args []string) error {
	fs := flag.NewFlagSet("readonly-root", flag.ContinueOnError)
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
		return runReadOnlyRootRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := readonlyroot.Analyze(collected)
	return printReadOnlyRootResult(r, *format)
}

func runReadOnlyRootRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := readonlyroot.Analyze(collected)
		if r.Summary.TotalServices > 0 {
			if err := printReadOnlyRootResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printReadOnlyRootResult(r readonlyroot.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(readonlyroot.FormatText(r))
	}
	return nil
}
