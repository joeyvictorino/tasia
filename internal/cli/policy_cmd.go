package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/policygen"
)

func runPolicy(args []string) error {
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text, json, or markdown")
	output := fs.String("output", "", "output file (default: stdout)")
	title := fs.String("title", "AI Stack Security Policy", "policy document title")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var findings = scanDir(absPath)
	if *recursive {
		findings = scanRecursive(absPath)
	}

	doc := policygen.GeneratePolicy(*title, absPath, findings)

	var out string
	switch *format {
	case "json":
		data, _ := json.MarshalIndent(doc, "", "  ")
		out = string(data)
	case "markdown", "md":
		out = policygen.FormatMarkdown(doc)
	default:
		out = policygen.FormatText(doc)
	}

	if *output != "" {
		if err := os.WriteFile(*output, []byte(out), 0644); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Policy written to %s\n", *output)
		return nil
	}

	fmt.Print(out)
	return nil
}
