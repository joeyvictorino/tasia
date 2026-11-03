package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/snmpaudit"
)

func runSnmpaudit(args []string) error {
	fs := flag.NewFlagSet("tasia snmpaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runSnmpauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("snmpaudit: %w", err)
	}

	r := snmpaudit.Analyze(c)
	printSnmpauditResult(r, *format)
	return nil
}

func runSnmpauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "snmpaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := snmpaudit.Analyze(c)
		printSnmpauditResult(r, format)
	}
	return nil
}

func printSnmpauditResult(r snmpaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(snmpaudit.FormatText(r))
	}
}
