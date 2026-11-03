package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/certpin"
)

func runCertpin(args []string) error {
	fs := flag.NewFlagSet("tasia certpin", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runCertpinRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("certpin: %w", err)
	}

	r := certpin.Analyze(c)
	printCertpinResult(r, *format)
	return nil
}

func runCertpinRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "certpin: skipping %s: %v\n", d, err)
			continue
		}
		r := certpin.Analyze(c)
		printCertpinResult(r, format)
	}
	return nil
}

func printCertpinResult(r certpin.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(certpin.FormatText(r))
	}
}
