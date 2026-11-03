package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/etcdaudit"
)

func runEtcdaudit(args []string) error {
	fs := flag.NewFlagSet("tasia etcdaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runEtcdauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("etcdaudit: %w", err)
	}

	r := etcdaudit.Analyze(c)
	printEtcdauditResult(r, *format)
	return nil
}

func runEtcdauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "etcdaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := etcdaudit.Analyze(c)
		printEtcdauditResult(r, format)
	}
	return nil
}

func printEtcdauditResult(r etcdaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(etcdaudit.FormatText(r))
	}
}
