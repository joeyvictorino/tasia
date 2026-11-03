package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/memcachedaudit"
)

func runMemcachedaudit(args []string) error {
	fs := flag.NewFlagSet("tasia memcachedaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runMemcachedauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("memcachedaudit: %w", err)
	}

	r := memcachedaudit.Analyze(c)
	printMemcachedauditResult(r, *format)
	return nil
}

func runMemcachedauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "memcachedaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := memcachedaudit.Analyze(c)
		printMemcachedauditResult(r, format)
	}
	return nil
}

func printMemcachedauditResult(r memcachedaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(memcachedaudit.FormatText(r))
	}
}
