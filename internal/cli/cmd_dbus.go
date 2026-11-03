package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/dbus"
)

func runDbus(args []string) error {
	fs := flag.NewFlagSet("tasia dbus", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runDbusRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("dbus: %w", err)
	}

	r := dbus.Analyze(c)
	printDbusResult(r, *format)
	return nil
}

func runDbusRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dbus: skipping %s: %v\n", d, err)
			continue
		}
		r := dbus.Analyze(c)
		printDbusResult(r, format)
	}
	return nil
}

func printDbusResult(r dbus.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(dbus.FormatText(r))
	}
}
