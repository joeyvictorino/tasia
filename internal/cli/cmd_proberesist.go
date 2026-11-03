package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/proberesist"
)

func runProberesist(args []string) error {
	fs := flag.NewFlagSet("tasia proberesist", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runProberesistRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("proberesist: %w", err)
	}

	r := proberesist.Analyze(c)
	printProberesistResult(r, *format)
	return nil
}

func runProberesistRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "proberesist: skipping %s: %v\n", d, err)
			continue
		}
		r := proberesist.Analyze(c)
		printProberesistResult(r, format)
	}
	return nil
}

func printProberesistResult(r proberesist.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(proberesist.FormatText(r))
	}
}
