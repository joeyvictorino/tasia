package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/entropy"
)

func runEntropy(args []string) error {
	fs := flag.NewFlagSet("entropy", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	threshold := fs.Float64("threshold", entropy.DefaultThreshold, "Shannon entropy threshold for flagging")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	abs, err := filepath.Abs(*path)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}

	if *recursive {
		return runEntropyRecursive(abs, *format, *threshold)
	}

	col, err := collect.WalkAndCollect(abs)
	if err != nil {
		return err
	}
	report := entropy.Analyze(col, *threshold)

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Print(entropy.FormatText(report))
	return nil
}

func runEntropyRecursive(root, format string, threshold float64) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		col, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		report := entropy.Analyze(col, threshold)
		if report.Summary.TotalEnvVars > 0 {
			if format == "json" {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return err
				}
			} else {
				fmt.Print(entropy.FormatText(report))
			}
		}
	}
	return nil
}
