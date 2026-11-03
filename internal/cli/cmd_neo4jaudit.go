package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/neo4jaudit"
)

func runNeo4jaudit(args []string) error {
	fs := flag.NewFlagSet("tasia neo4jaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runNeo4jauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("neo4jaudit: %w", err)
	}

	r := neo4jaudit.Analyze(c)
	printNeo4jauditResult(r, *format)
	return nil
}

func runNeo4jauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "neo4jaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := neo4jaudit.Analyze(c)
		printNeo4jauditResult(r, format)
	}
	return nil
}

func printNeo4jauditResult(r neo4jaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(neo4jaudit.FormatText(r))
	}
}
