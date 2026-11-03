package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/apiexpose"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runApiexpose(args []string) error {
	fs := flag.NewFlagSet("tasia apiexpose", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runApiexposeRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("apiexpose: %w", err)
	}

	r := apiexpose.Analyze(c)
	printApiexposeResult(r, *format)
	return nil
}

func runApiexposeRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "apiexpose: skipping %s: %v\n", d, err)
			continue
		}
		r := apiexpose.Analyze(c)
		printApiexposeResult(r, format)
	}
	return nil
}

func printApiexposeResult(r apiexpose.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(apiexpose.FormatText(r))
	}
}
