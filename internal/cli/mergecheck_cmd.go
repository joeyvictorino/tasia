package cli

import (
	"flag"
	"fmt"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/mergecheck"
)

func runMergeCheck(args []string) error {
	fs := flag.NewFlagSet("merge-check", flag.ContinueOnError)
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
		return runMergeCheckRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := mergecheck.SimulateMerge(collected)
	return printMergeResult(r, *format)
}

func runMergeCheckRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := mergecheck.SimulateMerge(collected)
		if len(r.Services) > 0 {
			if err := printMergeResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printMergeResult(r mergecheck.MergeResult, format string) error {
	switch format {
	case "json":
		out, err := mergecheck.FormatJSON(r)
		if err != nil {
			return err
		}
		fmt.Println(out)
	default:
		fmt.Print(mergecheck.FormatText(r))
	}
	return nil
}
