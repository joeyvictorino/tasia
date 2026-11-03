package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/pidlimit"
)

func runPidlimit(args []string) error {
	fs := flag.NewFlagSet("tasia pidlimit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runPidlimitRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("pidlimit: %w", err)
	}

	r := pidlimit.Analyze(c)
	printPidlimitResult(r, *format)
	return nil
}

func runPidlimitRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pidlimit: skipping %s: %v\n", d, err)
			continue
		}
		r := pidlimit.Analyze(c)
		printPidlimitResult(r, format)
	}
	return nil
}

func printPidlimitResult(r pidlimit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(pidlimit.FormatText(r))
	}
}
