package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/grpcaudit"
)

func runGrpcaudit(args []string) error {
	fs := flag.NewFlagSet("tasia grpcaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runGrpcauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("grpcaudit: %w", err)
	}

	r := grpcaudit.Analyze(c)
	printGrpcauditResult(r, *format)
	return nil
}

func runGrpcauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "grpcaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := grpcaudit.Analyze(c)
		printGrpcauditResult(r, format)
	}
	return nil
}

func printGrpcauditResult(r grpcaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(grpcaudit.FormatText(r))
	}
}
