package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/kernelparam"
)

func runKernelparam(args []string) error {
	fs := flag.NewFlagSet("tasia kernelparam", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runKernelparamRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("kernelparam: %w", err)
	}

	r := kernelparam.Analyze(c)
	printKernelparamResult(r, *format)
	return nil
}

func runKernelparamRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kernelparam: skipping %s: %v\n", d, err)
			continue
		}
		r := kernelparam.Analyze(c)
		printKernelparamResult(r, format)
	}
	return nil
}

func printKernelparamResult(r kernelparam.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(kernelparam.FormatText(r))
	}
}
