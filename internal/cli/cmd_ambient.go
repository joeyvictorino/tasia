package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/ambient"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runAmbient(args []string) error {
	fs := flag.NewFlagSet("tasia ambient", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runAmbientRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("ambient: %w", err)
	}

	r := ambient.Analyze(c)
	printAmbientResult(r, *format)
	return nil
}

func runAmbientRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ambient: skipping %s: %v\n", d, err)
			continue
		}
		r := ambient.Analyze(c)
		printAmbientResult(r, format)
	}
	return nil
}

func printAmbientResult(r ambient.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(ambient.FormatText(r))
	}
}
