package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/sbom"
)

func runSBOM(args []string) error {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text, json, or spdx-lite")
	output := fs.String("output", "", "output file (default: stdout)")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	_ = recursive

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	s := sbom.GenerateSBOM(absPath, collected)

	var out string
	switch *format {
	case "json":
		b, _ := json.MarshalIndent(s, "", "  ")
		out = string(b)
	case "spdx-lite":
		spdx := sbom.ToSPDXLite(s)
		b, _ := json.MarshalIndent(spdx, "", "  ")
		out = string(b)
	default:
		out = sbom.FormatText(s)
	}

	if *output != "" {
		return os.WriteFile(*output, []byte(out), 0644)
	}
	fmt.Print(out)
	return nil
}
