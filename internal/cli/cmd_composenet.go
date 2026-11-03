package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/composenet"
)

func runComposenet(args []string) error {
	fs := flag.NewFlagSet("tasia compose-network", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runComposenetRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("compose-network: %w", err)
	}

	r := composenet.Analyze(c)
	printComposenetResult(r, *format)
	return nil
}

func runComposenetRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "compose-network: skipping %s: %v\n", d, err)
			continue
		}
		r := composenet.Analyze(c)
		printComposenetResult(r, format)
	}
	return nil
}

func printComposenetResult(r composenet.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(composenet.FormatText(r))
	}
}
