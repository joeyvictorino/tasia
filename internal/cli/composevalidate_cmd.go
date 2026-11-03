package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/composevalidate"
)

func runComposeValidate(args []string) error {
	fs := flag.NewFlagSet("compose-validate", flag.ContinueOnError)
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
		return runComposeValidateRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := composevalidate.Analyze(collected)
	return printComposeValidateResult(r, *format)
}

func runComposeValidateRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := composevalidate.Analyze(collected)
		if r.Summary.FilesChecked > 0 {
			if err := printComposeValidateResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printComposeValidateResult(r composevalidate.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(composevalidate.FormatText(r))
	}
	return nil
}
