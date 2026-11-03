package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/loopdev"
)

func runLoopdev(args []string) error {
	fs := flag.NewFlagSet("tasia loopdev", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runLoopdevRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("loopdev: %w", err)
	}

	r := loopdev.Analyze(c)
	printLoopdevResult(r, *format)
	return nil
}

func runLoopdevRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "loopdev: skipping %s: %v\n", d, err)
			continue
		}
		r := loopdev.Analyze(c)
		printLoopdevResult(r, format)
	}
	return nil
}

func printLoopdevResult(r loopdev.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(loopdev.FormatText(r))
	}
}
