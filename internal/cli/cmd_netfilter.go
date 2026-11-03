package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/netfilter"
)

func runNetfilter(args []string) error {
	fs := flag.NewFlagSet("tasia netfilter", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runNetfilterRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("netfilter: %w", err)
	}

	r := netfilter.Analyze(c)
	printNetfilterResult(r, *format)
	return nil
}

func runNetfilterRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netfilter: skipping %s: %v\n", d, err)
			continue
		}
		r := netfilter.Analyze(c)
		printNetfilterResult(r, format)
	}
	return nil
}

func printNetfilterResult(r netfilter.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(netfilter.FormatText(r))
	}
}
