package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/cgroupns"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runCgroupNS(args []string) error {
	fs := flag.NewFlagSet("cgroup-ns", flag.ContinueOnError)
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
		return runCgroupNSRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := cgroupns.Analyze(collected)
	return printCgroupNSResult(r, *format)
}

func runCgroupNSRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := cgroupns.Analyze(collected)
		if r.Summary.TotalServices > 0 {
			if err := printCgroupNSResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printCgroupNSResult(r cgroupns.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(cgroupns.FormatText(r))
	}
	return nil
}
