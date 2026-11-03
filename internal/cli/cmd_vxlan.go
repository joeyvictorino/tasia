package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/vxlan"
)

func runVxlan(args []string) error {
	fs := flag.NewFlagSet("tasia vxlan", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runVxlanRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("vxlan: %w", err)
	}

	r := vxlan.Analyze(c)
	printVxlanResult(r, *format)
	return nil
}

func runVxlanRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vxlan: skipping %s: %v\n", d, err)
			continue
		}
		r := vxlan.Analyze(c)
		printVxlanResult(r, format)
	}
	return nil
}

func printVxlanResult(r vxlan.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(vxlan.FormatText(r))
	}
}
