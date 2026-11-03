package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/cronaudit"
)

func runCronaudit(args []string) error {
	fs := flag.NewFlagSet("tasia cronaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runCronauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("cronaudit: %w", err)
	}

	r := cronaudit.Analyze(c)
	printCronauditResult(r, *format)
	return nil
}

func runCronauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cronaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := cronaudit.Analyze(c)
		printCronauditResult(r, format)
	}
	return nil
}

func printCronauditResult(r cronaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(cronaudit.FormatText(r))
	}
}
