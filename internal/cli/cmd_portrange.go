package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/portrange"
)

func runPortrange(args []string) error {
	fs := flag.NewFlagSet("tasia portrange", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runPortrangeRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("portrange: %w", err)
	}

	r := portrange.Analyze(c)
	printPortrangeResult(r, *format)
	return nil
}

func runPortrangeRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "portrange: skipping %s: %v\n", d, err)
			continue
		}
		r := portrange.Analyze(c)
		printPortrangeResult(r, format)
	}
	return nil
}

func printPortrangeResult(r portrange.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(portrange.FormatText(r))
	}
}
