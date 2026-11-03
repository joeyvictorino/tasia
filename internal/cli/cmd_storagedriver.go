package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/storagedriver"
)

func runStoragedriver(args []string) error {
	fs := flag.NewFlagSet("tasia storagedriver", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runStoragedriverRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("storagedriver: %w", err)
	}

	r := storagedriver.Analyze(c)
	printStoragedriverResult(r, *format)
	return nil
}

func runStoragedriverRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "storagedriver: skipping %s: %v\n", d, err)
			continue
		}
		r := storagedriver.Analyze(c)
		printStoragedriverResult(r, format)
	}
	return nil
}

func printStoragedriverResult(r storagedriver.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(storagedriver.FormatText(r))
	}
}
