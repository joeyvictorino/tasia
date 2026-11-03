package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/grafanaaudit"
)

func runGrafanaaudit(args []string) error {
	fs := flag.NewFlagSet("tasia grafanaaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runGrafanaauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("grafanaaudit: %w", err)
	}

	r := grafanaaudit.Analyze(c)
	printGrafanaauditResult(r, *format)
	return nil
}

func runGrafanaauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "grafanaaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := grafanaaudit.Analyze(c)
		printGrafanaauditResult(r, format)
	}
	return nil
}

func printGrafanaauditResult(r grafanaaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(grafanaaudit.FormatText(r))
	}
}
