package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/ipcaudit"
)

func runIpcaudit(args []string) error {
	fs := flag.NewFlagSet("tasia ipcaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runIpcauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("ipcaudit: %w", err)
	}

	r := ipcaudit.Analyze(c)
	printIpcauditResult(r, *format)
	return nil
}

func runIpcauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ipcaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := ipcaudit.Analyze(c)
		printIpcauditResult(r, format)
	}
	return nil
}

func printIpcauditResult(r ipcaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(ipcaudit.FormatText(r))
	}
}
