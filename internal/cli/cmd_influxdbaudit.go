package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/influxdbaudit"
)

func runInfluxdbaudit(args []string) error {
	fs := flag.NewFlagSet("tasia influxdbaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runInfluxdbauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("influxdbaudit: %w", err)
	}

	r := influxdbaudit.Analyze(c)
	printInfluxdbauditResult(r, *format)
	return nil
}

func runInfluxdbauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "influxdbaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := influxdbaudit.Analyze(c)
		printInfluxdbauditResult(r, format)
	}
	return nil
}

func printInfluxdbauditResult(r influxdbaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(influxdbaudit.FormatText(r))
	}
}
