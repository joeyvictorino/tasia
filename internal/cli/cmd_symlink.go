package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/symlink"
)

func runSymlink(args []string) error {
	fs := flag.NewFlagSet("tasia symlink", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runSymlinkRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("symlink: %w", err)
	}

	r := symlink.Analyze(c)
	printSymlinkResult(r, *format)
	return nil
}

func runSymlinkRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "symlink: skipping %s: %v\n", d, err)
			continue
		}
		r := symlink.Analyze(c)
		printSymlinkResult(r, format)
	}
	return nil
}

func printSymlinkResult(r symlink.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(symlink.FormatText(r))
	}
}
