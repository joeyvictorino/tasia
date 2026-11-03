package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/filedescriptor"
)

func runFiledescriptor(args []string) error {
	fs := flag.NewFlagSet("filedescriptor", flag.ContinueOnError)
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
		return runFiledescriptorRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := filedescriptor.Analyze(collected)
	return printFiledescriptorResult(r, *format)
}

func runFiledescriptorRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := filedescriptor.Analyze(collected)
		if r.Summary.TotalFindings > 0 {
			if err := printFiledescriptorResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printFiledescriptorResult(r filedescriptor.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(filedescriptor.FormatText(r))
	}
	return nil
}
