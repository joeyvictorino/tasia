package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/linklocal"
)

func runLinklocal(args []string) error {
	fs := flag.NewFlagSet("tasia linklocal", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runLinklocalRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("linklocal: %w", err)
	}

	r := linklocal.Analyze(c)
	printLinklocalResult(r, *format)
	return nil
}

func runLinklocalRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "linklocal: skipping %s: %v\n", d, err)
			continue
		}
		r := linklocal.Analyze(c)
		printLinklocalResult(r, format)
	}
	return nil
}

func printLinklocalResult(r linklocal.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(linklocal.FormatText(r))
	}
}
