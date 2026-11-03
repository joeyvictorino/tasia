package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/nonroot"
)

func runNonroot(args []string) error {
	fs := flag.NewFlagSet("tasia nonroot", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runNonrootRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("nonroot: %w", err)
	}

	r := nonroot.Analyze(c)
	printNonrootResult(r, *format)
	return nil
}

func runNonrootRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nonroot: skipping %s: %v\n", d, err)
			continue
		}
		r := nonroot.Analyze(c)
		printNonrootResult(r, format)
	}
	return nil
}

func printNonrootResult(r nonroot.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(nonroot.FormatText(r))
	}
}
