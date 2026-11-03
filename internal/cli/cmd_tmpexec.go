package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/tmpexec"
)

func runTmpexec(args []string) error {
	fs := flag.NewFlagSet("tasia tmpexec", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runTmpexecRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("tmpexec: %w", err)
	}

	r := tmpexec.Analyze(c)
	printTmpexecResult(r, *format)
	return nil
}

func runTmpexecRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tmpexec: skipping %s: %v\n", d, err)
			continue
		}
		r := tmpexec.Analyze(c)
		printTmpexecResult(r, format)
	}
	return nil
}

func printTmpexecResult(r tmpexec.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(tmpexec.FormatText(r))
	}
}
