package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/cgroupescape"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runCgroupescape(args []string) error {
	fs := flag.NewFlagSet("tasia cgroupescape", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runCgroupescapeRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("cgroupescape: %w", err)
	}

	r := cgroupescape.Analyze(c)
	printCgroupescapeResult(r, *format)
	return nil
}

func runCgroupescapeRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cgroupescape: skipping %s: %v\n", d, err)
			continue
		}
		r := cgroupescape.Analyze(c)
		printCgroupescapeResult(r, format)
	}
	return nil
}

func printCgroupescapeResult(r cgroupescape.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(cgroupescape.FormatText(r))
	}
}
