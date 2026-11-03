package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/smtpaudit"
)

func runSmtpaudit(args []string) error {
	fs := flag.NewFlagSet("tasia smtpaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runSmtpauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("smtpaudit: %w", err)
	}

	r := smtpaudit.Analyze(c)
	printSmtpauditResult(r, *format)
	return nil
}

func runSmtpauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "smtpaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := smtpaudit.Analyze(c)
		printSmtpauditResult(r, format)
	}
	return nil
}

func printSmtpauditResult(r smtpaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(smtpaudit.FormatText(r))
	}
}
