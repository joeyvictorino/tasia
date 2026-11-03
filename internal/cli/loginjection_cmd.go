package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/loginjection"
)

func runLoginjection(args []string) error {
	fs := flag.NewFlagSet("loginjection", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	if *recursive {
		return runLoginjectionRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := loginjection.Analyze(collected)
	return printLoginjectionResult(r, *format)
}

func runLoginjectionRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := loginjection.Analyze(collected)
		if r.Summary.TotalFindings > 0 {
			if err := printLoginjectionResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printLoginjectionResult(r loginjection.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(loginjection.FormatText(r))
	}
	return nil
}
