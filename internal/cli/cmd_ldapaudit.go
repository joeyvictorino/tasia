package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/ldapaudit"
)

func runLdapaudit(args []string) error {
	fs := flag.NewFlagSet("tasia ldapaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runLdapauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("ldapaudit: %w", err)
	}

	r := ldapaudit.Analyze(c)
	printLdapauditResult(r, *format)
	return nil
}

func runLdapauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ldapaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := ldapaudit.Analyze(c)
		printLdapauditResult(r, format)
	}
	return nil
}

func printLdapauditResult(r ldapaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(ldapaudit.FormatText(r))
	}
}
