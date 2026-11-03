package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/surrealdbaudit"
)

func runSurrealdbaudit(args []string) error {
	fs := flag.NewFlagSet("tasia surrealdbaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runSurrealdbauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("surrealdbaudit: %w", err)
	}

	r := surrealdbaudit.Analyze(c)
	printSurrealdbauditResult(r, *format)
	return nil
}

func runSurrealdbauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "surrealdbaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := surrealdbaudit.Analyze(c)
		printSurrealdbauditResult(r, format)
	}
	return nil
}

func printSurrealdbauditResult(r surrealdbaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(surrealdbaudit.FormatText(r))
	}
}
