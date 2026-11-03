package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/vpnaudit"
)

func runVpnaudit(args []string) error {
	fs := flag.NewFlagSet("tasia vpnaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runVpnauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("vpnaudit: %w", err)
	}

	r := vpnaudit.Analyze(c)
	printVpnauditResult(r, *format)
	return nil
}

func runVpnauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vpnaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := vpnaudit.Analyze(c)
		printVpnauditResult(r, format)
	}
	return nil
}

func printVpnauditResult(r vpnaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(vpnaudit.FormatText(r))
	}
}
