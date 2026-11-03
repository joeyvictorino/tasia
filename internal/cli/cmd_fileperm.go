package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/fileperm"
)

func runFileperm(args []string) error {
	fs := flag.NewFlagSet("tasia fileperm", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runFilepermRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("fileperm: %w", err)
	}

	r := fileperm.Analyze(c)
	printFilepermResult(r, *format)
	return nil
}

func runFilepermRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fileperm: skipping %s: %v\n", d, err)
			continue
		}
		r := fileperm.Analyze(c)
		printFilepermResult(r, format)
	}
	return nil
}

func printFilepermResult(r fileperm.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(fileperm.FormatText(r))
	}
}
