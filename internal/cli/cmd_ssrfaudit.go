package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/ssrfaudit"
)

func runSsrfaudit(args []string) error {
	fs := flag.NewFlagSet("tasia ssrfaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runSsrfauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("ssrfaudit: %w", err)
	}

	r := ssrfaudit.Analyze(c)
	printSsrfauditResult(r, *format)
	return nil
}

func runSsrfauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssrfaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := ssrfaudit.Analyze(c)
		printSsrfauditResult(r, format)
	}
	return nil
}

func printSsrfauditResult(r ssrfaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(ssrfaudit.FormatText(r))
	}
}
