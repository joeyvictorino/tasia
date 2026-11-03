package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/rethinkdbaudit"
)

func runRethinkdbaudit(args []string) error {
	fs := flag.NewFlagSet("tasia rethinkdbaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runRethinkdbauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("rethinkdbaudit: %w", err)
	}

	r := rethinkdbaudit.Analyze(c)
	printRethinkdbauditResult(r, *format)
	return nil
}

func runRethinkdbauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rethinkdbaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := rethinkdbaudit.Analyze(c)
		printRethinkdbauditResult(r, format)
	}
	return nil
}

func printRethinkdbauditResult(r rethinkdbaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(rethinkdbaudit.FormatText(r))
	}
}
