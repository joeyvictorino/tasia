package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/procmount"
)

func runProcmount(args []string) error {
	fs := flag.NewFlagSet("tasia procmount", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runProcmountRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("procmount: %w", err)
	}

	r := procmount.Analyze(c)
	printProcmountResult(r, *format)
	return nil
}

func runProcmountRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "procmount: skipping %s: %v\n", d, err)
			continue
		}
		r := procmount.Analyze(c)
		printProcmountResult(r, format)
	}
	return nil
}

func printProcmountResult(r procmount.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(procmount.FormatText(r))
	}
}
