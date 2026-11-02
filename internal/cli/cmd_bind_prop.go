package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/bindprop"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runBindProp(args []string) error {
	fs := flag.NewFlagSet("bind-prop", flag.ContinueOnError)
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
		return runBindPropRecursive(absPath, *format)
	}
	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}
	r := bindprop.Analyze(collected)
	return printBindPropResult(r, *format)
}

func runBindPropRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := bindprop.Analyze(collected)
		if r.Summary.TotalServices > 0 {
			if err := printBindPropResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printBindPropResult(r bindprop.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(bindprop.FormatText(r))
	}
	return nil
}
