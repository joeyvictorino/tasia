package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/sambaaudit"
)

func runSambaaudit(args []string) error {
	fs := flag.NewFlagSet("tasia sambaaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runSambaauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("sambaaudit: %w", err)
	}

	r := sambaaudit.Analyze(c)
	printSambaauditResult(r, *format)
	return nil
}

func runSambaauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sambaaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := sambaaudit.Analyze(c)
		printSambaauditResult(r, format)
	}
	return nil
}

func printSambaauditResult(r sambaaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(sambaaudit.FormatText(r))
	}
}
