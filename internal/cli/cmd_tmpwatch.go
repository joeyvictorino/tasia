package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/tmpwatch"
)

func runTmpwatch(args []string) error {
	fs := flag.NewFlagSet("tasia tmpwatch", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runTmpwatchRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("tmpwatch: %w", err)
	}

	r := tmpwatch.Analyze(c)
	printTmpwatchResult(r, *format)
	return nil
}

func runTmpwatchRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tmpwatch: skipping %s: %v\n", d, err)
			continue
		}
		r := tmpwatch.Analyze(c)
		printTmpwatchResult(r, format)
	}
	return nil
}

func printTmpwatchResult(r tmpwatch.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(tmpwatch.FormatText(r))
	}
}
