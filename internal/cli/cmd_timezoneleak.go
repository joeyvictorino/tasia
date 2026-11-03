package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/timezoneleak"
)

func runTimezoneleak(args []string) error {
	fs := flag.NewFlagSet("tasia timezoneleak", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runTimezoneleakRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("timezoneleak: %w", err)
	}

	r := timezoneleak.Analyze(c)
	printTimezoneleakResult(r, *format)
	return nil
}

func runTimezoneleakRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "timezoneleak: skipping %s: %v\n", d, err)
			continue
		}
		r := timezoneleak.Analyze(c)
		printTimezoneleakResult(r, format)
	}
	return nil
}

func printTimezoneleakResult(r timezoneleak.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(timezoneleak.FormatText(r))
	}
}
