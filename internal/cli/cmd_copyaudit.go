package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/copyaudit"
)

func runCopyaudit(args []string) error {
	fs := flag.NewFlagSet("tasia copyaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runCopyauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("copyaudit: %w", err)
	}

	r := copyaudit.Analyze(c)
	printCopyauditResult(r, *format)
	return nil
}

func runCopyauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "copyaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := copyaudit.Analyze(c)
		printCopyauditResult(r, format)
	}
	return nil
}

func printCopyauditResult(r copyaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(copyaudit.FormatText(r))
	}
}
