package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/deporder"
)

func runDeporder(args []string) error {
	fs := flag.NewFlagSet("tasia deporder", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runDeporderRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("deporder: %w", err)
	}

	r := deporder.Analyze(c)
	printDeporderResult(r, *format)
	return nil
}

func runDeporderRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "deporder: skipping %s: %v\n", d, err)
			continue
		}
		r := deporder.Analyze(c)
		printDeporderResult(r, format)
	}
	return nil
}

func printDeporderResult(r deporder.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(deporder.FormatText(r))
	}
}
