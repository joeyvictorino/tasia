package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/buildcache"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runBuildcache(args []string) error {
	fs := flag.NewFlagSet("tasia buildcache", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runBuildcacheRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("buildcache: %w", err)
	}

	r := buildcache.Analyze(c)
	printBuildcacheResult(r, *format)
	return nil
}

func runBuildcacheRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "buildcache: skipping %s: %v\n", d, err)
			continue
		}
		r := buildcache.Analyze(c)
		printBuildcacheResult(r, format)
	}
	return nil
}

func printBuildcacheResult(r buildcache.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(buildcache.FormatText(r))
	}
}
