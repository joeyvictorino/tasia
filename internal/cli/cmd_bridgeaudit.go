package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/bridgeaudit"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runBridgeaudit(args []string) error {
	fs := flag.NewFlagSet("tasia bridgeaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runBridgeauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("bridgeaudit: %w", err)
	}

	r := bridgeaudit.Analyze(c)
	printBridgeauditResult(r, *format)
	return nil
}

func runBridgeauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bridgeaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := bridgeaudit.Analyze(c)
		printBridgeauditResult(r, format)
	}
	return nil
}

func printBridgeauditResult(r bridgeaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(bridgeaudit.FormatText(r))
	}
}
