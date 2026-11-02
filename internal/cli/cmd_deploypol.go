package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/deploypol"
)

func runDeploypol(args []string) error {
	fs := flag.NewFlagSet("deploy-policy", flag.ContinueOnError)
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
		return runDeploypolRecursive(absPath, *format)
	}
	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}
	r := deploypol.Analyze(collected)
	return printDeploypolResult(r, *format)
}

func runDeploypolRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := deploypol.Analyze(collected)
		if r.Summary.TotalServices > 0 {
			if err := printDeploypolResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printDeploypolResult(r deploypol.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(deploypol.FormatText(r))
		return nil
	}
}
