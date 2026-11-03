package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/sshaudit"
)

func runSshaudit(args []string) error {
	fs := flag.NewFlagSet("tasia sshaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runSshauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("sshaudit: %w", err)
	}

	r := sshaudit.Analyze(c)
	printSshauditResult(r, *format)
	return nil
}

func runSshauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sshaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := sshaudit.Analyze(c)
		printSshauditResult(r, format)
	}
	return nil
}

func printSshauditResult(r sshaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(sshaudit.FormatText(r))
	}
}
