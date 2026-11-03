package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/envexpand"
)

func runEnvexpand(args []string) error {
	fs := flag.NewFlagSet("tasia envexpand", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runEnvexpandRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("envexpand: %w", err)
	}

	r := envexpand.Analyze(c)
	printEnvexpandResult(r, *format)
	return nil
}

func runEnvexpandRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "envexpand: skipping %s: %v\n", d, err)
			continue
		}
		r := envexpand.Analyze(c)
		printEnvexpandResult(r, format)
	}
	return nil
}

func printEnvexpandResult(r envexpand.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(envexpand.FormatText(r))
	}
}
