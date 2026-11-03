package cli

import (
	"flag"
	"fmt"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/portmap"
)

func runPortMap(args []string) error {
	fs := flag.NewFlagSet("port-map", flag.ContinueOnError)
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
		return runPortMapRecursive(absPath, *format)
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	r := portmap.Analyze(collected)
	return printPortMapResult(r, *format)
}

func runPortMapRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		collected, err := collect.WalkAndCollect(d)
		if err != nil {
			continue
		}
		r := portmap.Analyze(collected)
		if len(r.Entries) > 0 {
			if err := printPortMapResult(r, format); err != nil {
				return err
			}
		}
	}
	return nil
}

func printPortMapResult(r portmap.PortMapResult, format string) error {
	switch format {
	case "json":
		out, err := portmap.FormatJSON(r)
		if err != nil {
			return err
		}
		fmt.Println(out)
	default:
		fmt.Print(portmap.FormatText(r))
	}
	return nil
}
