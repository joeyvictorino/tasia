package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/composeoverride"
)

func runComposeOverride(args []string) error {
	fs := flag.NewFlagSet("compose-override", flag.ContinueOnError)
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
		return runComposeOverrideRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := composeoverride.Analyze(collected)
	return printComposeOverrideResult(r, *format)
}

func runComposeOverrideRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := composeoverride.Analyze(collected)
		if r.Summary.OverrideFiles > 0 {
			if err := printComposeOverrideResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printComposeOverrideResult(r composeoverride.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(composeoverride.FormatText(r))
	}
	return nil
}
