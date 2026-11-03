package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/tlsconfig"
)

func runTlsconfig(args []string) error {
	fs := flag.NewFlagSet("tlsconfig", flag.ContinueOnError)
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
		return runTlsconfigRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := tlsconfig.Analyze(collected)
	return printTlsconfigResult(r, *format)
}

func runTlsconfigRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := tlsconfig.Analyze(collected)
		if r.Summary.TotalFindings > 0 {
			if err := printTlsconfigResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printTlsconfigResult(r tlsconfig.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(tlsconfig.FormatText(r))
	}
	return nil
}
