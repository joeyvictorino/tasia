package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/securityopt"
)

func runSecurityopt(args []string) error {
	fs := flag.NewFlagSet("tasia securityopt", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runSecurityoptRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("securityopt: %w", err)
	}

	r := securityopt.Analyze(c)
	printSecurityoptResult(r, *format)
	return nil
}

func runSecurityoptRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "securityopt: skipping %s: %v\n", d, err)
			continue
		}
		r := securityopt.Analyze(c)
		printSecurityoptResult(r, format)
	}
	return nil
}

func printSecurityoptResult(r securityopt.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(securityopt.FormatText(r))
	}
}
