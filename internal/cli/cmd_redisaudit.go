package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/redisaudit"
)

func runRedisaudit(args []string) error {
	fs := flag.NewFlagSet("tasia redisaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runRedisauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("redisaudit: %w", err)
	}

	r := redisaudit.Analyze(c)
	printRedisauditResult(r, *format)
	return nil
}

func runRedisauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "redisaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := redisaudit.Analyze(c)
		printRedisauditResult(r, format)
	}
	return nil
}

func printRedisauditResult(r redisaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(redisaudit.FormatText(r))
	}
}
