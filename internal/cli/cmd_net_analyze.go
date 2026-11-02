package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/netanalyze"
)

func runNetAnalyze(args []string) error {
	fs := flag.NewFlagSet("net-analyze", flag.ContinueOnError)
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
		return runNetAnalyzeRecursive(absPath, *format)
	}
	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}
	r := netanalyze.AnalyzeNetworks(collected)
	return printNetAnalyzeResult(r, *format)
}

func runNetAnalyzeRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := netanalyze.AnalyzeNetworks(collected)
		if len(r.Networks) > 0 || len(r.Findings) > 0 {
			if err := printNetAnalyzeResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printNetAnalyzeResult(r netanalyze.NetworkAnalysis, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(netanalyze.FormatText(r))
	}
	return nil
}
