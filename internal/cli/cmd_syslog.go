package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/syslog"
)

func runSyslog(args []string) error {
	fs := flag.NewFlagSet("tasia syslog", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runSyslogRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("syslog: %w", err)
	}

	r := syslog.Analyze(c)
	printSyslogResult(r, *format)
	return nil
}

func runSyslogRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "syslog: skipping %s: %v\n", d, err)
			continue
		}
		r := syslog.Analyze(c)
		printSyslogResult(r, format)
	}
	return nil
}

func printSyslogResult(r syslog.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(syslog.FormatText(r))
	}
}
