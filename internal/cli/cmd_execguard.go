package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/execguard"
)

func runExecguard(args []string) error {
	fs := flag.NewFlagSet("tasia execguard", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runExecguardRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("execguard: %w", err)
	}

	r := execguard.Analyze(c)
	printExecguardResult(r, *format)
	return nil
}

func runExecguardRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "execguard: skipping %s: %v\n", d, err)
			continue
		}
		r := execguard.Analyze(c)
		printExecguardResult(r, format)
	}
	return nil
}

func printExecguardResult(r execguard.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(execguard.FormatText(r))
	}
}
