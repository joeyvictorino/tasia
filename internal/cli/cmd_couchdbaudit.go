package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/couchdbaudit"
)

func runCouchdbaudit(args []string) error {
	fs := flag.NewFlagSet("tasia couchdbaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runCouchdbauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("couchdbaudit: %w", err)
	}

	r := couchdbaudit.Analyze(c)
	printCouchdbauditResult(r, *format)
	return nil
}

func runCouchdbauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "couchdbaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := couchdbaudit.Analyze(c)
		printCouchdbauditResult(r, format)
	}
	return nil
}

func printCouchdbauditResult(r couchdbaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(couchdbaudit.FormatText(r))
	}
}
