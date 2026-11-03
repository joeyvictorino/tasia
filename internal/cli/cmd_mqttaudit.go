package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/mqttaudit"
)

func runMqttaudit(args []string) error {
	fs := flag.NewFlagSet("tasia mqttaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("mqttaudit: %w", err)
	}
	report := mqttaudit.Analyze(c)
	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	default:
		fmt.Print(mqttaudit.FormatText(report))
	}
	return nil
}
