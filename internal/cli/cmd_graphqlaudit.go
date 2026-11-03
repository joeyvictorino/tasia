package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/graphqlaudit"
)

func runGraphqlaudit(args []string) error {
	fs := flag.NewFlagSet("tasia graphqlaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *recursive {
		return runGraphqlauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("graphqlaudit: %w", err)
	}

	r := graphqlaudit.Analyze(c)
	printGraphqlauditResult(r, *format)
	return nil
}

func runGraphqlauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "graphqlaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := graphqlaudit.Analyze(c)
		printGraphqlauditResult(r, format)
	}
	return nil
}

func printGraphqlauditResult(r graphqlaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(graphqlaudit.FormatText(r))
	}
}
