package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/mcastaudit"
)

func runMcastaudit(args []string) error {
	fs := flag.NewFlagSet("tasia mcastaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runMcastauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("mcastaudit: %w", err)
	}

	r := mcastaudit.Analyze(c)
	printMcastauditResult(r, *format)
	return nil
}

func runMcastauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcastaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := mcastaudit.Analyze(c)
		printMcastauditResult(r, format)
	}
	return nil
}

func printMcastauditResult(r mcastaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(mcastaudit.FormatText(r))
	}
}
