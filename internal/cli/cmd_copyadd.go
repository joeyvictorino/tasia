package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/copyadd"
)

func runCopyadd(args []string) error {
	fs := flag.NewFlagSet("tasia copyadd", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runCopyaddRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("copyadd: %w", err)
	}

	r := copyadd.Analyze(c)
	printCopyaddResult(r, *format)
	return nil
}

func runCopyaddRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "copyadd: skipping %s: %v\n", d, err)
			continue
		}
		r := copyadd.Analyze(c)
		printCopyaddResult(r, format)
	}
	return nil
}

func printCopyaddResult(r copyadd.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(copyadd.FormatText(r))
	}
}
