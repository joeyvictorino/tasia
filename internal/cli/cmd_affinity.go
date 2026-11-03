package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/affinity"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runAffinity(args []string) error {
	fs := flag.NewFlagSet("tasia affinity", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runAffinityRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("affinity: %w", err)
	}

	r := affinity.Analyze(c)
	printAffinityResult(r, *format)
	return nil
}

func runAffinityRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "affinity: skipping %s: %v\n", d, err)
			continue
		}
		r := affinity.Analyze(c)
		printAffinityResult(r, format)
	}
	return nil
}

func printAffinityResult(r affinity.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(affinity.FormatText(r))
	}
}
