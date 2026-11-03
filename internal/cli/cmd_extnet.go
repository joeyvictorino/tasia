package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/extnet"
)

func runExtnet(args []string) error {
	fs := flag.NewFlagSet("tasia extnet", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runExtnetRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("extnet: %w", err)
	}

	r := extnet.Analyze(c)
	printExtnetResult(r, *format)
	return nil
}

func runExtnetRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "extnet: skipping %s: %v\n", d, err)
			continue
		}
		r := extnet.Analyze(c)
		printExtnetResult(r, format)
	}
	return nil
}

func printExtnetResult(r extnet.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(extnet.FormatText(r))
	}
}
