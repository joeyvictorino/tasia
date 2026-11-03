package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/overlayfs"
)

func runOverlayfs(args []string) error {
	fs := flag.NewFlagSet("tasia overlayfs", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runOverlayfsRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("overlayfs: %w", err)
	}

	r := overlayfs.Analyze(c)
	printOverlayfsResult(r, *format)
	return nil
}

func runOverlayfsRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "overlayfs: skipping %s: %v\n", d, err)
			continue
		}
		r := overlayfs.Analyze(c)
		printOverlayfsResult(r, format)
	}
	return nil
}

func printOverlayfsResult(r overlayfs.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(overlayfs.FormatText(r))
	}
}
