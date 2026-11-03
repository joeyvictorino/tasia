package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/cephaudit"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runCephaudit(args []string) error {
	fs := flag.NewFlagSet("tasia cephaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runCephauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("cephaudit: %w", err)
	}

	r := cephaudit.Analyze(c)
	printCephauditResult(r, *format)
	return nil
}

func runCephauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cephaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := cephaudit.Analyze(c)
		printCephauditResult(r, format)
	}
	return nil
}

func printCephauditResult(r cephaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(cephaudit.FormatText(r))
	}
}
