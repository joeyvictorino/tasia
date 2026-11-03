package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/initprocess"
)

func runInitProcess(args []string) error {
	fs := flag.NewFlagSet("init-process", flag.ContinueOnError)
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
		return runInitProcessRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := initprocess.Analyze(collected)
	return printInitProcessResult(r, *format)
}

func runInitProcessRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := initprocess.Analyze(collected)
		if r.Summary.TotalServices > 0 {
			if err := printInitProcessResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printInitProcessResult(r initprocess.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(initprocess.FormatText(r))
	}
	return nil
}
