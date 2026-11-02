package cli

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/layeraudit"
)

func runLayerAudit(args []string) error {
	fs := flag.NewFlagSet("layer-audit", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	_ = *recursive // reserved for future use
	collected, err := collect.WalkAndCollect(*path)
	if err != nil {
		return err
	}

	report := layeraudit.Analyze(*collected)

	switch *format {
	case "json":
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	default:
		fmt.Print(layeraudit.FormatText(report))
	}
	return nil
}
