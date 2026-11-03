package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/secretrotation"
)

func runSecretrotation(args []string) error {
	fs := flag.NewFlagSet("tasia secretrotation", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runSecretrotationRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("secretrotation: %w", err)
	}

	r := secretrotation.Analyze(c)
	printSecretrotationResult(r, *format)
	return nil
}

func runSecretrotationRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "secretrotation: skipping %s: %v\n", d, err)
			continue
		}
		r := secretrotation.Analyze(c)
		printSecretrotationResult(r, format)
	}
	return nil
}

func printSecretrotationResult(r secretrotation.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(secretrotation.FormatText(r))
	}
}
