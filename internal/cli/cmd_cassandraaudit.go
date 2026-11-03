package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/cassandraaudit"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runCassandraaudit(args []string) error {
	fs := flag.NewFlagSet("tasia cassandraaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runCassandraauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("cassandraaudit: %w", err)
	}

	r := cassandraaudit.Analyze(c)
	printCassandraauditResult(r, *format)
	return nil
}

func runCassandraauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cassandraaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := cassandraaudit.Analyze(c)
		printCassandraauditResult(r, format)
	}
	return nil
}

func printCassandraauditResult(r cassandraaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(cassandraaudit.FormatText(r))
	}
}
