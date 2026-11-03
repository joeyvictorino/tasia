package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/scylladbaudit"
)

func runScylladbaudit(args []string) error {
	fs := flag.NewFlagSet("tasia scylladbaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runScylladbauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("scylladbaudit: %w", err)
	}

	r := scylladbaudit.Analyze(c)
	printScylladbauditResult(r, *format)
	return nil
}

func runScylladbauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scylladbaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := scylladbaudit.Analyze(c)
		printScylladbauditResult(r, format)
	}
	return nil
}

func printScylladbauditResult(r scylladbaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(scylladbaudit.FormatText(r))
	}
}
