package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/timescaledbaudit"
)

func runTimescaledbaudit(args []string) error {
	fs := flag.NewFlagSet("tasia timescaledbaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runTimescaledbauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("timescaledbaudit: %w", err)
	}

	r := timescaledbaudit.Analyze(c)
	printTimescaledbauditResult(r, *format)
	return nil
}

func runTimescaledbauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "timescaledbaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := timescaledbaudit.Analyze(c)
		printTimescaledbauditResult(r, format)
	}
	return nil
}

func printTimescaledbauditResult(r timescaledbaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(timescaledbaudit.FormatText(r))
	}
}
