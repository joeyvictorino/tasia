package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/milvusaudit"
)

func runMilvusaudit(args []string) error {
	fs := flag.NewFlagSet("tasia milvusaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runMilvusauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("milvusaudit: %w", err)
	}

	r := milvusaudit.Analyze(c)
	printMilvusauditResult(r, *format)
	return nil
}

func runMilvusauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "milvusaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := milvusaudit.Analyze(c)
		printMilvusauditResult(r, format)
	}
	return nil
}

func printMilvusauditResult(r milvusaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(milvusaudit.FormatText(r))
	}
}
