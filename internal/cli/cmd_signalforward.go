package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/signalforward"
)

func runSignalforward(args []string) error {
	fs := flag.NewFlagSet("tasia signalforward", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runSignalforwardRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("signalforward: %w", err)
	}

	r := signalforward.Analyze(c)
	printSignalforwardResult(r, *format)
	return nil
}

func runSignalforwardRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "signalforward: skipping %s: %v\n", d, err)
			continue
		}
		r := signalforward.Analyze(c)
		printSignalforwardResult(r, format)
	}
	return nil
}

func printSignalforwardResult(r signalforward.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(signalforward.FormatText(r))
	}
}
