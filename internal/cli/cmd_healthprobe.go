package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/healthprobe"
)

func runHealthProbe(args []string) error {
	fs := flag.NewFlagSet("health-probe", flag.ContinueOnError)
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
		return runHealthProbeRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := healthprobe.Analyze(collected)
	return printHealthProbeResult(r, *format)
}

func runHealthProbeRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := healthprobe.Analyze(collected)
		if r.Summary.TotalServices > 0 {
			if err := printHealthProbeResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printHealthProbeResult(r healthprobe.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(healthprobe.FormatText(r))
	}
	return nil
}
