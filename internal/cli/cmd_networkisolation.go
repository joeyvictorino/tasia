package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/networkisolation"
)

func runNetworkisolation(args []string) error {
	fs := flag.NewFlagSet("tasia networkisolation", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runNetworkisolationRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("networkisolation: %w", err)
	}

	r := networkisolation.Analyze(c)
	printNetworkisolationResult(r, *format)
	return nil
}

func runNetworkisolationRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "networkisolation: skipping %s: %v\n", d, err)
			continue
		}
		r := networkisolation.Analyze(c)
		printNetworkisolationResult(r, format)
	}
	return nil
}

func printNetworkisolationResult(r networkisolation.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(networkisolation.FormatText(r))
	}
}
