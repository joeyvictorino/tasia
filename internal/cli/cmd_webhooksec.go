package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/webhooksec"
)

func runWebhooksec(args []string) error {
	fs := flag.NewFlagSet("tasia webhooksec", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runWebhooksecRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("webhooksec: %w", err)
	}

	r := webhooksec.Analyze(c)
	printWebhooksecResult(r, *format)
	return nil
}

func runWebhooksecRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "webhooksec: skipping %s: %v\n", d, err)
			continue
		}
		r := webhooksec.Analyze(c)
		printWebhooksecResult(r, format)
	}
	return nil
}

func printWebhooksecResult(r webhooksec.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(webhooksec.FormatText(r))
	}
}
