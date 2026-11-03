package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/netalias"
)

func runNetalias(args []string) error {
	fs := flag.NewFlagSet("tasia netalias", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runNetaliasRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("netalias: %w", err)
	}

	r := netalias.Analyze(c)
	printNetaliasResult(r, *format)
	return nil
}

func runNetaliasRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netalias: skipping %s: %v\n", d, err)
			continue
		}
		r := netalias.Analyze(c)
		printNetaliasResult(r, format)
	}
	return nil
}

func printNetaliasResult(r netalias.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(netalias.FormatText(r))
	}
}
