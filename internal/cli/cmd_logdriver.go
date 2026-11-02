package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/logdriver"
)

func runLogdriver(args []string) error {
	fs := flag.NewFlagSet("tasia logdriver", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runLogdriverRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("logdriver: %w", err)
	}

	r := logdriver.Analyze(c)
	printLogdriverResult(r, *format)
	return nil
}

func runLogdriverRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "logdriver: skipping %s: %v\n", d, err)
			continue
		}
		r := logdriver.Analyze(c)
		printLogdriverResult(r, format)
	}
	return nil
}

func printLogdriverResult(r logdriver.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(logdriver.FormatText(r))
	}
}
