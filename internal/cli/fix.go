package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/config"
	"github.com/joeyvictorino/tasia/internal/ignore"
	"github.com/joeyvictorino/tasia/internal/remediate"
	"github.com/joeyvictorino/tasia/internal/rules"
)

func runFix(args []string) error {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var findings []rules.Finding
	if *recursive {
		findings = scanRecursive(absPath)
	} else {
		collected, err := collect.WalkAndCollect(absPath)
		if err != nil {
			return err
		}
		if len(collected.ParseErrors) > 0 {
			fmt.Fprintln(os.Stderr, "tasia fix: cannot parse config; fix parse errors first")
			os.Exit(2)
		}
		findings = rules.Evaluate(collected)

		if pol, err := ignore.Load(absPath); err == nil {
			pol.AddInline(ignore.ScanInline(absPath))
			findings = filterFindings(findings, pol)
		}
		if cfg, err := config.Load(absPath); err == nil {
			findings = applySeverityOverrides(findings, cfg)
		}
	}

	remediations := remediate.SuggestAll(findings)

	switch *format {
	case "json":
		data, err := json.MarshalIndent(remediations, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		fmt.Print(remediate.FormatText(remediations))
	}

	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "tasia fix: %d remediation(s) suggested\n", len(remediations))
	}
	return nil
}
