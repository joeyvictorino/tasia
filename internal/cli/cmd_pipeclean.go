package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/pipeclean"
)

func runPipeclean(args []string) error {
	fs := flag.NewFlagSet("tasia pipeclean", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runPipecleanRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("pipeclean: %w", err)
	}

	r := pipeclean.Analyze(c)
	printPipecleanResult(r, *format)
	return nil
}

func runPipecleanRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pipeclean: skipping %s: %v\n", d, err)
			continue
		}
		r := pipeclean.Analyze(c)
		printPipecleanResult(r, format)
	}
	return nil
}

func printPipecleanResult(r pipeclean.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(pipeclean.FormatText(r))
	}
}
