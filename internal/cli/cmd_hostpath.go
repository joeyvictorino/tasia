package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/hostpath"
)

func runHostpath(args []string) error {
	fs := flag.NewFlagSet("tasia hostpath", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runHostpathRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("hostpath: %w", err)
	}

	r := hostpath.Analyze(c)
	printHostpathResult(r, *format)
	return nil
}

func runHostpathRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hostpath: skipping %s: %v\n", d, err)
			continue
		}
		r := hostpath.Analyze(c)
		printHostpathResult(r, format)
	}
	return nil
}

func printHostpathResult(r hostpath.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(hostpath.FormatText(r))
	}
}
