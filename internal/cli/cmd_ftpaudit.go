package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/ftpaudit"
)

func runFtpaudit(args []string) error {
	fs := flag.NewFlagSet("tasia ftpaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runFtpauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("ftpaudit: %w", err)
	}

	r := ftpaudit.Analyze(c)
	printFtpauditResult(r, *format)
	return nil
}

func runFtpauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ftpaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := ftpaudit.Analyze(c)
		printFtpauditResult(r, format)
	}
	return nil
}

func printFtpauditResult(r ftpaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(ftpaudit.FormatText(r))
	}
}
