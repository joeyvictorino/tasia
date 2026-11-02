package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/dnsrebind"
)

func runDnsrebind(args []string) error {
	fs := flag.NewFlagSet("tasia dnsrebind", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runDnsrebindRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("dnsrebind: %w", err)
	}

	r := dnsrebind.Analyze(c)
	printDnsrebindResult(r, *format)
	return nil
}

func runDnsrebindRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnsrebind: skipping %s: %v\n", d, err)
			continue
		}
		r := dnsrebind.Analyze(c)
		printDnsrebindResult(r, format)
	}
	return nil
}

func printDnsrebindResult(r dnsrebind.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(dnsrebind.FormatText(r))
	}
}
