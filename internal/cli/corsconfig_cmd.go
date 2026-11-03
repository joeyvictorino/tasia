package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/corsconfig"
)

func runCorsconfig(args []string) error {
	fs := flag.NewFlagSet("corsconfig", flag.ContinueOnError)
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
		return runCorsconfigRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := corsconfig.Analyze(collected)
	return printCorsconfigResult(r, *format)
}

func runCorsconfigRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := corsconfig.Analyze(collected)
		if r.Summary.TotalFindings > 0 {
			if err := printCorsconfigResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printCorsconfigResult(r corsconfig.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(corsconfig.FormatText(r))
	}
	return nil
}
