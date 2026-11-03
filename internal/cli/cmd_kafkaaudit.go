package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/kafkaaudit"
)

func runKafkaaudit(args []string) error {
	fs := flag.NewFlagSet("tasia kafkaaudit", flag.ContinueOnError)
	path := fs.String("path", ".", "project path")
	format := fs.String("format", "text", "output format (text|json)")
	recursive := fs.Bool("recursive", false, "scan subdirectories recursively")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *recursive {
		return runKafkaauditRecursive(*path, *format)
	}

	c, err := collect.WalkAndCollect(*path)
	if err != nil {
		return fmt.Errorf("kafkaaudit: %w", err)
	}

	r := kafkaaudit.Analyze(c)
	printKafkaauditResult(r, *format)
	return nil
}

func runKafkaauditRecursive(root, format string) error {
	dirs := findScanDirs(root)
	for _, d := range dirs {
		c, err := collect.WalkAndCollect(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kafkaaudit: skipping %s: %v\n", d, err)
			continue
		}
		r := kafkaaudit.Analyze(c)
		printKafkaauditResult(r, format)
	}
	return nil
}

func printKafkaauditResult(r kafkaaudit.Report, format string) {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	default:
		fmt.Print(kafkaaudit.FormatText(r))
	}
}
