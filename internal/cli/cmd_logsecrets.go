package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/logsecrets"
)

func runLogsecrets(args []string) error {
	fs := flag.NewFlagSet("tasia logsecrets", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runLogsecretsRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("logsecrets: %w", err)
	}

	r := logsecrets.Analyze(c)
	printLogsecretsResult(r, *format)
	return nil
}

func runLogsecretsRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "logsecrets: skipping %s: %v\n", d, err)
			continue
		}
		r := logsecrets.Analyze(c)
		printLogsecretsResult(r, format)
	}
	return nil
}

func printLogsecretsResult(r logsecrets.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(logsecrets.FormatText(r))
	}
}
