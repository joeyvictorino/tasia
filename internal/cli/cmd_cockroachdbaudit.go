package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/cockroachdbaudit"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runCockroachdbaudit(args []string) error {
	fs := flag.NewFlagSet("tasia cockroachdbaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runCockroachdbauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("cockroachdbaudit: %w", err)
	}

	r := cockroachdbaudit.Analyze(c)
	printCockroachdbauditResult(r, *format)
	return nil
}

func runCockroachdbauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cockroachdbaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := cockroachdbaudit.Analyze(c)
		printCockroachdbauditResult(r, format)
	}
	return nil
}

func printCockroachdbauditResult(r cockroachdbaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(cockroachdbaudit.FormatText(r))
	}
}
