package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/trustchain"
)

func runTrustchain(args []string) error {
	fs := flag.NewFlagSet("tasia trust-chain", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("trust-chain: %w", err)
	}

	r := trustchain.Analyze(c)
	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(trustchain.FormatText(r))
	}
	return nil
}
