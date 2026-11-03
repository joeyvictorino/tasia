package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/envfile"
)

func runEnvfile(args []string) error {
	fs := flag.NewFlagSet("tasia envfile", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runEnvfileRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("envfile: %w", err)
	}

	r := envfile.Analyze(c)
	printEnvfileResult(r, *format)
	return nil
}

func runEnvfileRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "envfile: skipping %s: %v\n", d, err)
			continue
		}
		r := envfile.Analyze(c)
		printEnvfileResult(r, format)
	}
	return nil
}

func printEnvfileResult(r envfile.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(envfile.FormatText(r))
	}
}
