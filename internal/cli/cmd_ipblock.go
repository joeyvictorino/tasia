package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/ipblock"
)

func runIpblock(args []string) error {
	fs := flag.NewFlagSet("tasia ipblock", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runIpblockRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("ipblock: %w", err)
	}

	r := ipblock.Analyze(c)
	printIpblockResult(r, *format)
	return nil
}

func runIpblockRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ipblock: skipping %s: %v\n", d, err)
			continue
		}
		r := ipblock.Analyze(c)
		printIpblockResult(r, format)
	}
	return nil
}

func printIpblockResult(r ipblock.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(ipblock.FormatText(r))
	}
}
