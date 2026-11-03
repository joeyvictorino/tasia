package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/swaplimit"
)

func runSwaplimit(args []string) error {
	fs := flag.NewFlagSet("tasia swaplimit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runSwaplimitRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("swaplimit: %w", err)
	}

	r := swaplimit.Analyze(c)
	printSwaplimitResult(r, *format)
	return nil
}

func runSwaplimitRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "swaplimit: skipping %s: %v\n", d, err)
			continue
		}
		r := swaplimit.Analyze(c)
		printSwaplimitResult(r, format)
	}
	return nil
}

func printSwaplimitResult(r swaplimit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(swaplimit.FormatText(r))
	}
}
