package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/qdrantaudit"
)

func runQdrantaudit(args []string) error {
	fs := flag.NewFlagSet("tasia qdrantaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runQdrantauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("qdrantaudit: %w", err)
	}

	r := qdrantaudit.Analyze(c)
	printQdrantauditResult(r, *format)
	return nil
}

func runQdrantauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "qdrantaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := qdrantaudit.Analyze(c)
		printQdrantauditResult(r, format)
	}
	return nil
}

func printQdrantauditResult(r qdrantaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(qdrantaudit.FormatText(r))
	}
}
