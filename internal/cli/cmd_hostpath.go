package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/hostpath"
)

func runHostpath(args []string) error {
	fs := flag.NewFlagSet("tasia hostpath", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := collect.Run(*path, *recursive)
	if err != nil {
		return fmt.Errorf("collect: %w", err)
	}

	r := hostpath.Analyze(c)

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		fmt.Print(hostpath.FormatText(r))
	}
	return nil
}
