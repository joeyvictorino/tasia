package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/riskmatrix"
	"github.com/joeyvictorino/tasia/internal/rules"
)

func runRiskMatrix(args []string) error {
	fs := flag.NewFlagSet("risk-matrix", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
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

	findings := rules.Evaluate(collected)
	m := riskmatrix.BuildMatrix(findings)

	switch *format {
	case "json":
		b, _ := json.MarshalIndent(m, "", "  ")
		fmt.Println(string(b))
	default:
		fmt.Print(riskmatrix.FormatText(m))
	}
	return nil
}
