package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/dnstls"
)

func runDnstls(args []string) error {
	fs := flag.NewFlagSet("tasia dnstls", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runDnstlsRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("dnstls: %w", err)
	}

	r := dnstls.Analyze(c)
	printDnstlsResult(r, *format)
	return nil
}

func runDnstlsRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstls: skipping %s: %v\n", d, err)
			continue
		}
		r := dnstls.Analyze(c)
		printDnstlsResult(r, format)
	}
	return nil
}

func printDnstlsResult(r dnstls.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(dnstls.FormatText(r))
	}
}
