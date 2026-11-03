package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/netanalyze"
)

func runNetwork(args []string) error {
	fs := flag.NewFlagSet("network", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text, json, or dot")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var collected *collect.Collected
	if *recursive {
		dirs := findScanDirs(absPath)
		merged := &collect.Collected{Root: absPath}
		for _, d := range dirs {
			c, err := collect.WalkAndCollect(d)
			if err != nil {
				continue
			}
			merged.ComposeFiles = append(merged.ComposeFiles, c.ComposeFiles...)
		}
		collected = merged
	} else {
		collected, err = collect.WalkAndCollect(absPath)
		if err != nil {
			return err
		}
	}

	analysis := netanalyze.AnalyzeNetworks(collected)

	switch *format {
	case "json":
		out, _ := json.MarshalIndent(analysis, "", "  ")
		fmt.Println(string(out))
	case "dot":
		fmt.Print(netanalyze.FormatDOT(analysis))
	default:
		fmt.Print(netanalyze.FormatText(analysis))
	}
	return nil
}
