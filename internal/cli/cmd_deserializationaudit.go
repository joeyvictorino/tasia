package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/deserializationaudit"
)

func runDeserializationaudit(args []string) error {
	fs := flag.NewFlagSet("tasia deserializationaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runDeserializationauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("deserializationaudit: %w", err)
	}

	r := deserializationaudit.Analyze(c)
	printDeserializationauditResult(r, *format)
	return nil
}

func runDeserializationauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "deserializationaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := deserializationaudit.Analyze(c)
		printDeserializationauditResult(r, format)
	}
	return nil
}

func printDeserializationauditResult(r deserializationaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(deserializationaudit.FormatText(r))
	}
}
