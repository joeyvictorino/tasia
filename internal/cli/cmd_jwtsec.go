package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/jwtsec"
)

func runJwtsec(args []string) error {
	fs := flag.NewFlagSet("tasia jwtsec", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runJwtsecRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("jwtsec: %w", err)
	}

	r := jwtsec.Analyze(c)
	printJwtsecResult(r, *format)
	return nil
}

func runJwtsecRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "jwtsec: skipping %s: %v\n", d, err)
			continue
		}
		r := jwtsec.Analyze(c)
		printJwtsecResult(r, format)
	}
	return nil
}

func printJwtsecResult(r jwtsec.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(jwtsec.FormatText(r))
	}
}
