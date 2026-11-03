package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/proxyproto"
)

func runProxyproto(args []string) error {
	fs := flag.NewFlagSet("tasia proxyproto", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runProxyprotoRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("proxyproto: %w", err)
	}

	r := proxyproto.Analyze(c)
	printProxyprotoResult(r, *format)
	return nil
}

func runProxyprotoRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "proxyproto: skipping %s: %v\n", d, err)
			continue
		}
		r := proxyproto.Analyze(c)
		printProxyprotoResult(r, format)
	}
	return nil
}

func printProxyprotoResult(r proxyproto.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(proxyproto.FormatText(r))
	}
}
