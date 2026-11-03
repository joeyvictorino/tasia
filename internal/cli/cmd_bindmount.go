package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/bindmount"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runBindmount(args []string) error {
	fs := flag.NewFlagSet("tasia bindmount", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runBindmountRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("bindmount: %w", err)
	}

	r := bindmount.Analyze(c)
	printBindmountResult(r, *format)
	return nil
}

func runBindmountRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bindmount: skipping %s: %v\n", d, err)
			continue
		}
		r := bindmount.Analyze(c)
		printBindmountResult(r, format)
	}
	return nil
}

func printBindmountResult(r bindmount.Report, format string) {
	switch format {
	case "json":
		fmt.Print(bindmount.FormatJSON(r))
	default:
		fmt.Print(bindmount.FormatText(r))
	}
}
