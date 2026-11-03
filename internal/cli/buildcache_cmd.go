package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/buildcache"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runBuildCache(args []string) error {
	fs := flag.NewFlagSet("build-cache", flag.ContinueOnError)
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
		return runBuildCacheRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := buildcache.Analyze(collected)
	return printBuildCacheResult(r, *format)
}

func runBuildCacheRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := buildcache.Analyze(collected)
		if r.Summary.TotalFiles > 0 {
			if err := printBuildCacheResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printBuildCacheResult(r buildcache.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(buildcache.FormatText(r))
	}
	return nil
}
