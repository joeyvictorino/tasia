package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/logdriver"
)

func runLogDriver(args []string) error {
	fs := flag.NewFlagSet("log-driver", flag.ContinueOnError)
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
		return runLogDriverRecursive(absPath, *format)
	}
	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}
	r := logdriver.Analyze(collected)
	return printLogDriverResult(r, *format)
}

func runLogDriverRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := logdriver.Analyze(collected)
		if r.Summary.TotalServices > 0 {
			if err := printLogDriverResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printLogDriverResult(r logdriver.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(logdriver.FormatText(r))
	}
	return nil
}
