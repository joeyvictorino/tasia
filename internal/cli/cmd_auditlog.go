package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/auditlog"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runAuditlog(args []string) error {
	fs := flag.NewFlagSet("tasia auditlog", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runAuditlogRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("auditlog: %w", err)
	}

	r := auditlog.Analyze(c)
	printAuditlogResult(r, *format)
	return nil
}

func runAuditlogRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "auditlog: skipping %s: %v\n", d, err)
			continue
		}
		r := auditlog.Analyze(c)
		printAuditlogResult(r, format)
	}
	return nil
}

func printAuditlogResult(r auditlog.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(auditlog.FormatText(r))
	}
}
