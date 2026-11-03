package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/oauth2audit"
)

func runOauth2audit(args []string) error {
	fs := flag.NewFlagSet("tasia oauth2audit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runOauth2auditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("oauth2audit: %w", err)
	}

	r := oauth2audit.Analyze(c)
	printOauth2auditResult(r, *format)
	return nil
}

func runOauth2auditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "oauth2audit: skipping %s: %v\n", d, err)
			continue
		}
		r := oauth2audit.Analyze(c)
		printOauth2auditResult(r, format)
	}
	return nil
}

func printOauth2auditResult(r oauth2audit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(oauth2audit.FormatText(r))
	}
}
