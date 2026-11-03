package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/clickhouseaudit"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runClickhouseaudit(args []string) error {
	fs := flag.NewFlagSet("tasia clickhouseaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runClickhouseauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("clickhouseaudit: %w", err)
	}

	r := clickhouseaudit.Analyze(c)
	printClickhouseauditResult(r, *format)
	return nil
}

func runClickhouseauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "clickhouseaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := clickhouseaudit.Analyze(c)
		printClickhouseauditResult(r, format)
	}
	return nil
}

func printClickhouseauditResult(r clickhouseaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(clickhouseaudit.FormatText(r))
	}
}
