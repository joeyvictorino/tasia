package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/layeraudit"
)

func runLayeraudit(args []string) error {
	fs := flag.NewFlagSet("tasia layeraudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runLayerauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("layeraudit: %w", err)
	}

	r := layeraudit.Analyze(*c)
	printLayerauditResult(r, *format)
	return nil
}

func runLayerauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "layeraudit: skipping %s: %v\n", d, err)
			continue
		}
		r := layeraudit.Analyze(*c)
		printLayerauditResult(r, format)
	}
	return nil
}

func printLayerauditResult(r layeraudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(layeraudit.FormatText(r))
	}
}
