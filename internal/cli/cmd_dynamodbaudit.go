package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/dynamodbaudit"
)

func runDynamodbaudit(args []string) error {
	fs := flag.NewFlagSet("tasia dynamodbaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runDynamodbauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("dynamodbaudit: %w", err)
	}

	r := dynamodbaudit.Analyze(c)
	printDynamodbauditResult(r, *format)
	return nil
}

func runDynamodbauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dynamodbaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := dynamodbaudit.Analyze(c)
		printDynamodbauditResult(r, format)
	}
	return nil
}

func printDynamodbauditResult(r dynamodbaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(dynamodbaudit.FormatText(r))
	}
}
