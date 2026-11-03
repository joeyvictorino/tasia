package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/capbound"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runCapbound(args []string) error {
	fs := flag.NewFlagSet("tasia capbound", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runCapboundRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("capbound: %w", err)
	}

	r := capbound.Analyze(c)
	printCapboundResult(r, *format)
	return nil
}

func runCapboundRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "capbound: skipping %s: %v\n", d, err)
			continue
		}
		r := capbound.Analyze(c)
		printCapboundResult(r, format)
	}
	return nil
}

func printCapboundResult(r capbound.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(capbound.FormatText(r))
	}
}
