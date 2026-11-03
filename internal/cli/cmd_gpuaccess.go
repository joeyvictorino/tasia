package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/gpuaccess"
)

func runGpuaccess(args []string) error {
	fs := flag.NewFlagSet("tasia gpuaccess", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runGpuaccessRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("gpuaccess: %w", err)
	}

	r := gpuaccess.Analyze(c)
	printGpuaccessResult(r, *format)
	return nil
}

func runGpuaccessRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gpuaccess: skipping %s: %v\n", d, err)
			continue
		}
		r := gpuaccess.Analyze(c)
		printGpuaccessResult(r, format)
	}
	return nil
}

func printGpuaccessResult(r gpuaccess.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(gpuaccess.FormatText(r))
	}
}
