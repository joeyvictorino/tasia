package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/tlsversion"
)

func runTlsversion(args []string) error {
	fs := flag.NewFlagSet("tasia tlsversion", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runTlsversionRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("tlsversion: %w", err)
	}

	r := tlsversion.Analyze(c)
	printTlsversionResult(r, *format)
	return nil
}

func runTlsversionRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tlsversion: skipping %s: %v\n", d, err)
			continue
		}
		r := tlsversion.Analyze(c)
		printTlsversionResult(r, format)
	}
	return nil
}

func printTlsversionResult(r tlsversion.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(tlsversion.FormatText(r))
	}
}
