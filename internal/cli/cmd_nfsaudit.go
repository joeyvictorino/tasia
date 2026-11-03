package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/nfsaudit"
)

func runNfsaudit(args []string) error {
	fs := flag.NewFlagSet("tasia nfsaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *recursive {
		return runNfsauditRecursive(*path, *format)
	}
	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("nfsaudit: %w", err)
	}
	r := nfsaudit.Analyze(c)
	printNfsauditResult(r, *format)
	return nil
}

func runNfsauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nfsaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := nfsaudit.Analyze(c)
		printNfsauditResult(r, format)
	}
	return nil
}

func printNfsauditResult(r nfsaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(nfsaudit.FormatText(r))
	}
}
