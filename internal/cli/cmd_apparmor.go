package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/apparmor"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runAppArmor(args []string) error {
	fs := flag.NewFlagSet("apparmor", flag.ContinueOnError)
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
		return runAppArmorRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := apparmor.Analyze(collected)
	return printAppArmorResult(r, *format)
}

func runAppArmorRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := apparmor.Analyze(collected)
		if r.Summary.TotalServices > 0 {
			if err := printAppArmorResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printAppArmorResult(r apparmor.Report, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(apparmor.FormatText(r))
	}
	return nil
}
