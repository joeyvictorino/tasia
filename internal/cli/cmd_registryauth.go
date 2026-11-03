package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/registryauth"
)

func runRegistryauth(args []string) error {
	fs := flag.NewFlagSet("tasia registryauth", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runRegistryauthRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("registryauth: %w", err)
	}

	r := registryauth.Analyze(c)
	printRegistryauthResult(r, *format)
	return nil
}

func runRegistryauthRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "registryauth: skipping %s: %v\n", d, err)
			continue
		}
		r := registryauth.Analyze(c)
		printRegistryauthResult(r, format)
	}
	return nil
}

func printRegistryauthResult(r registryauth.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(registryauth.FormatText(r))
	}
}
