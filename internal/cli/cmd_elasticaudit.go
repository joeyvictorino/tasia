package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/elasticaudit"
)

func runElasticaudit(args []string) error {
	fs := flag.NewFlagSet("tasia elasticaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runElasticauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("elasticaudit: %w", err)
	}

	r := elasticaudit.Analyze(c)
	printElasticauditResult(r, *format)
	return nil
}

func runElasticauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "elasticaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := elasticaudit.Analyze(c)
		printElasticauditResult(r, format)
	}
	return nil
}

func printElasticauditResult(r elasticaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(elasticaudit.FormatText(r))
	}
}
