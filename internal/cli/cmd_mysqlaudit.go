package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/mysqlaudit"
)

func runMysqlaudit(args []string) error {
	fs := flag.NewFlagSet("tasia mysqlaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runMysqlauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("mysqlaudit: %w", err)
	}

	r := mysqlaudit.Analyze(c)
	printMysqlauditResult(r, *format)
	return nil
}

func runMysqlauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mysqlaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := mysqlaudit.Analyze(c)
		printMysqlauditResult(r, format)
	}
	return nil
}

func printMysqlauditResult(r mysqlaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(mysqlaudit.FormatText(r))
	}
}
