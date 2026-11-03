package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/mongoaudit"
)

func runMongoaudit(args []string) error {
	fs := flag.NewFlagSet("tasia mongoaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runMongoauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("mongoaudit: %w", err)
	}

	r := mongoaudit.Analyze(c)
	printMongoauditResult(r, *format)
	return nil
}

func runMongoauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mongoaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := mongoaudit.Analyze(c)
		printMongoauditResult(r, format)
	}
	return nil
}

func printMongoauditResult(r mongoaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(mongoaudit.FormatText(r))
	}
}
