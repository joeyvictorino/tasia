package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/socketaudit"
)

func runSocketAudit(args []string) error {
	fs := flag.NewFlagSet("socket-audit", flag.ContinueOnError)
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
		return runSocketAuditRecursive(absPath, *format)
	}
	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}
	r := socketaudit.Analyze(collected)
	return printSocketAuditResult(r, *format)
}

func runSocketAuditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := socketaudit.Analyze(collected)
		if r.Summary.TotalServices > 0 {
			if err := printSocketAuditResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printSocketAuditResult(r socketaudit.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(socketaudit.FormatText(r))
	}
	return nil
}
