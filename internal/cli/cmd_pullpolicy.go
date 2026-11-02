package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/pullpolicy"
)

func runPullpolicy(args []string) error {
	fs := flag.NewFlagSet("tasia pullpolicy", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runPullpolicyRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("pullpolicy: %w", err)
	}

	r := pullpolicy.Analyze(c)
	printPullpolicyResult(r, *format)
	return nil
}

func runPullpolicyRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pullpolicy: skipping %s: %v\n", d, err)
			continue
		}
		r := pullpolicy.Analyze(c)
		printPullpolicyResult(r, format)
	}
	return nil
}

func printPullpolicyResult(r pullpolicy.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(pullpolicy.FormatText(r))
	}
}
