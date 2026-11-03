package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/procexec"
)

func runProcexec(args []string) error {
	fs := flag.NewFlagSet("tasia procexec", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runProcexecRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("procexec: %w", err)
	}

	r := procexec.Analyze(c)
	printProcexecResult(r, *format)
	return nil
}

func runProcexecRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "procexec: skipping %s: %v\n", d, err)
			continue
		}
		r := procexec.Analyze(c)
		printProcexecResult(r, format)
	}
	return nil
}

func printProcexecResult(r procexec.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(procexec.FormatText(r))
	}
}
