package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/postgresaudit"
)

func runPostgresaudit(args []string) error {
	fs := flag.NewFlagSet("tasia postgresaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runPostgresauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("postgresaudit: %w", err)
	}

	r := postgresaudit.Analyze(c)
	printPostgresauditResult(r, *format)
	return nil
}

func runPostgresauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "postgresaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := postgresaudit.Analyze(c)
		printPostgresauditResult(r, format)
	}
	return nil
}

func printPostgresauditResult(r postgresaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(postgresaudit.FormatText(r))
	}
}
