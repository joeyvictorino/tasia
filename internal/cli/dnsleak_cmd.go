package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/dnsleak"
)

func runDnsleak(args []string) error {
	fs := flag.NewFlagSet("dnsleak", flag.ContinueOnError)
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
		return runDnsleakRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := dnsleak.Analyze(collected)
	return printDnsleakResult(r, *format)
}

func runDnsleakRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := dnsleak.Analyze(collected)
		if r.Summary.TotalFindings > 0 {
			if err := printDnsleakResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printDnsleakResult(r dnsleak.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(dnsleak.FormatText(r))
	}
	return nil
}
