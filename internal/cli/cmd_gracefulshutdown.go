package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/gracefulshutdown"
)

func runGracefulshutdown(args []string) error {
	fs := flag.NewFlagSet("tasia gracefulshutdown", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runGracefulshutdownRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("gracefulshutdown: %w", err)
	}

	r := gracefulshutdown.Analyze(c)
	printGracefulshutdownResult(r, *format)
	return nil
}

func runGracefulshutdownRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gracefulshutdown: skipping %s: %v\n", d, err)
			continue
		}
		r := gracefulshutdown.Analyze(c)
		printGracefulshutdownResult(r, format)
	}
	return nil
}

func printGracefulshutdownResult(r gracefulshutdown.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(gracefulshutdown.FormatText(r))
	}
}
