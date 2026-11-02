package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/tmpdir"
)

func runTmpdir(args []string) error {
	fs := flag.NewFlagSet("tasia tmpdir", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runTmpdirRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("tmpdir: %w", err)
	}

	r := tmpdir.Analyze(c)
	printTmpdirResult(r, *format)
	return nil
}

func runTmpdirRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tmpdir: skipping %s: %v\n", d, err)
			continue
		}
		r := tmpdir.Analyze(c)
		printTmpdirResult(r, format)
	}
	return nil
}

func printTmpdirResult(r tmpdir.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(tmpdir.FormatText(r))
	}
}
