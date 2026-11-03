package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/apigateway"
	"github.com/joeyvictorino/tasia/internal/collect"
)

func runApigateway(args []string) error {
	fs := flag.NewFlagSet("tasia apigateway", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runApigatewayRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("apigateway: %w", err)
	}

	r := apigateway.Analyze(c)
	printApigatewayResult(r, *format)
	return nil
}

func runApigatewayRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "apigateway: skipping %s: %v\n", d, err)
			continue
		}
		r := apigateway.Analyze(c)
		printApigatewayResult(r, format)
	}
	return nil
}

func printApigatewayResult(r apigateway.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(apigateway.FormatText(r))
	}
}
