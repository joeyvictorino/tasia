package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/dnssecaudit"
)

func runDnssecaudit(args []string) error {
	fs := flag.NewFlagSet("tasia dnssecaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runDnssecauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("dnssecaudit: %w", err)
	}

	r := dnssecaudit.Analyze(c)
	printDnssecauditResult(r, *format)
	return nil
}

func runDnssecauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnssecaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := dnssecaudit.Analyze(c)
		printDnssecauditResult(r, format)
	}
	return nil
}

func printDnssecauditResult(r dnssecaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(dnssecaudit.FormatText(r))
	}
}
