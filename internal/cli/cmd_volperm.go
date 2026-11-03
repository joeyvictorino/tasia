package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/volperm"
)

func runVolperm(args []string) error {
	fs := flag.NewFlagSet("tasia volperm", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runVolpermRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("volperm: %w", err)
	}

	r := volperm.Analyze(c)
	printVolpermResult(r, *format)
	return nil
}

func runVolpermRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "volperm: skipping %s: %v\n", d, err)
			continue
		}
		r := volperm.Analyze(c)
		printVolpermResult(r, format)
	}
	return nil
}

func printVolpermResult(r volperm.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(volperm.FormatText(r))
	}
}
