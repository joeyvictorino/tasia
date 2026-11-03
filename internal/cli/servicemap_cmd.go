package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/servicemap"
)

func runServiceMap(args []string) error {
	fs := flag.NewFlagSet("service-map", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text, json, or dot")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	if *recursive {
		return runServiceMapRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	return printServiceMapResult(servicemap.Analyze(collected), *format)
}

func runServiceMapRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := servicemap.Analyze(collected)
		if r.Stats.TotalServices > 0 {
			if err := printServiceMapResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printServiceMapResult(sm servicemap.ServiceMap, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(sm)
	case "dot":
		fmt.Print(servicemap.FormatDOT(sm))
	default:
		fmt.Print(servicemap.FormatText(sm))
	}
	return nil
}
