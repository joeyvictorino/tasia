package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/envtemplate"
)

func runEnvtemplate(args []string) error {
	fs := flag.NewFlagSet("tasia env-template", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "env", "output format (env|text|json)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("env-template: %w", err)
	}

	r := envtemplate.Analyze(c)
	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	case "text":
		fmt.Print(envtemplate.FormatText(r))
	default:
		fmt.Print(envtemplate.FormatEnvExample(r))
	}
	return nil
}
