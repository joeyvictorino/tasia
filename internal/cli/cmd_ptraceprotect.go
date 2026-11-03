package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/ptraceprotect"
)

func runPtraceprotect(args []string) error {
	fs := flag.NewFlagSet("tasia ptraceprotect", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runPtraceprotectRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("ptraceprotect: %w", err)
	}

	r := ptraceprotect.Analyze(c)
	printPtraceprotectResult(r, *format)
	return nil
}

func runPtraceprotectRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ptraceprotect: skipping %s: %v\n", d, err)
			continue
		}
		r := ptraceprotect.Analyze(c)
		printPtraceprotectResult(r, format)
	}
	return nil
}

func printPtraceprotectResult(r ptraceprotect.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(ptraceprotect.FormatText(r))
	}
}
