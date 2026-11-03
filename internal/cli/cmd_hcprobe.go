package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/hcprobe"
)

func runHcprobe(args []string) error {
	fs := flag.NewFlagSet("tasia hcprobe", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runHcprobeRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("hcprobe: %w", err)
	}

	r := hcprobe.Analyze(c)
	printHcprobeResult(r, *format)
	return nil
}

func runHcprobeRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hcprobe: skipping %s: %v\n", d, err)
			continue
		}
		r := hcprobe.Analyze(c)
		printHcprobeResult(r, format)
	}
	return nil
}

func printHcprobeResult(r hcprobe.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(hcprobe.FormatText(r))
	}
}
