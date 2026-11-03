package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/logrotate"
)

func runLogrotate(args []string) error {
	fs := flag.NewFlagSet("tasia logrotate", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runLogrotateRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("logrotate: %w", err)
	}

	r := logrotate.Analyze(c)
	printLogrotateResult(r, *format)
	return nil
}

func runLogrotateRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "logrotate: skipping %s: %v\n", d, err)
			continue
		}
		r := logrotate.Analyze(c)
		printLogrotateResult(r, format)
	}
	return nil
}

func printLogrotateResult(r logrotate.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(logrotate.FormatText(r))
	}
}
