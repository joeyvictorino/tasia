package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/nsenter"
)

func runNsenter(args []string) error {
	fs := flag.NewFlagSet("tasia nsenter", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runNsenterRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("nsenter: %w", err)
	}

	r := nsenter.Analyze(c)
	printNsenterResult(r, *format)
	return nil
}

func runNsenterRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nsenter: skipping %s: %v\n", d, err)
			continue
		}
		r := nsenter.Analyze(c)
		printNsenterResult(r, format)
	}
	return nil
}

func printNsenterResult(r nsenter.Report, format string) {
	switch format {
	case "json":
		fmt.Print(nsenter.FormatJSON(r))
	default:
		fmt.Print(nsenter.FormatText(r))
	}
}
