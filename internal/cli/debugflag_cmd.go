package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/debugflag"
)

func runDebugflag(args []string) error {
	fs := flag.NewFlagSet("debugflag", flag.ContinueOnError)
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
		return runDebugflagRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := debugflag.Analyze(collected)
	return printDebugflagResult(r, *format)
}

func runDebugflagRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := debugflag.Analyze(collected)
		if r.Summary.TotalFindings > 0 {
			if err := printDebugflagResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printDebugflagResult(r debugflag.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(debugflag.FormatText(r))
	}
	return nil
}
