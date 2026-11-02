package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/socketperm"
)

func runSocketperm(args []string) error {
	fs := flag.NewFlagSet("tasia socketperm", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runSocketpermRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("socketperm: %w", err)
	}

	r := socketperm.Analyze(c)
	printSocketpermResult(r, *format)
	return nil
}

func runSocketpermRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "socketperm: skipping %s: %v\n", d, err)
			continue
		}
		r := socketperm.Analyze(c)
		printSocketpermResult(r, format)
	}
	return nil
}

func printSocketpermResult(r socketperm.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(socketperm.FormatText(r))
	}
}
