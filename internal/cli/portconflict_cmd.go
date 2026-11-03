package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/portconflict"
)

func runPortConflict(args []string) error {
	fs := flag.NewFlagSet("port-conflict", flag.ContinueOnError)
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
		return runPortConflictRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := portconflict.Analyze(collected)
	return printPortConflictResult(r, *format)
}

func runPortConflictRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := portconflict.Analyze(collected)
		if r.Summary.TotalPorts > 0 {
			if err := printPortConflictResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printPortConflictResult(r portconflict.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(portconflict.FormatText(r))
	}
	return nil
}
