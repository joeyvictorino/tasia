package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/consulaudit"
)

func runConsulaudit(args []string) error {
	fs := flag.NewFlagSet("tasia consulaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runConsulauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("consulaudit: %w", err)
	}

	r := consulaudit.Analyze(c)
	printConsulauditResult(r, *format)
	return nil
}

func runConsulauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "consulaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := consulaudit.Analyze(c)
		printConsulauditResult(r, format)
	}
	return nil
}

func printConsulauditResult(r consulaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(consulaudit.FormatText(r))
	}
}
