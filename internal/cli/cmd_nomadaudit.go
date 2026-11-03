package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/nomadaudit"
)

func runNomadaudit(args []string) error {
	fs := flag.NewFlagSet("tasia nomadaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runNomadauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("nomadaudit: %w", err)
	}

	r := nomadaudit.Analyze(c)
	printNomadauditResult(r, *format)
	return nil
}

func runNomadauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nomadaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := nomadaudit.Analyze(c)
		printNomadauditResult(r, format)
	}
	return nil
}

func printNomadauditResult(r nomadaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(nomadaudit.FormatText(r))
	}
}
