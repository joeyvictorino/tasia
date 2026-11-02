package cli

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/joeyvictorino/tasia/internal/snapshot"
)

func runDrift(args []string) error {
	fs := flag.NewFlagSet("drift", flag.ContinueOnError)
	basePath := fs.String("base", "", "base snapshot file")
	currentPath := fs.String("current", "", "current snapshot file")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *basePath == "" || *currentPath == "" {
		fmt.Println("Usage: tasia drift --base <snapshot.json> --current <snapshot.json>")
		return fmt.Errorf("--base and --current are required")
	}

	base, err := snapshot.LoadSnapshot(*basePath)
	if err != nil {
		return fmt.Errorf("loading base snapshot: %w", err)
	}
	current, err := snapshot.LoadSnapshot(*currentPath)
	if err != nil {
		return fmt.Errorf("loading current snapshot: %w", err)
	}

	result := snapshot.ComputeDrift(base, current)

	switch *format {
	case "json":
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	default:
		printDrift(result)
	}
	return nil
}

func printDrift(d snapshot.DriftResult) {
	fmt.Printf("Drift Analysis\n")
	fmt.Printf("  Base checksum:    %s\n", d.BaseChecksum)
	fmt.Printf("  Current checksum: %s\n", d.CurrentChecksum)
	fmt.Printf("  Drift score:      %.2f\n\n", d.DriftScore)
	fmt.Printf("  Unchanged: %d\n", d.Unchanged)
	fmt.Printf("  New:       %d\n", len(d.NewFindings))
	fmt.Printf("  Resolved:  %d\n\n", len(d.Resolved))

	if len(d.NewFindings) > 0 {
		fmt.Println("New Findings:")
		for _, f := range d.NewFindings {
			fmt.Printf("  [%s] %s — %s (%s)\n", f.Severity, f.RuleID, f.Message, f.File)
		}
		fmt.Println()
	}
	if len(d.Resolved) > 0 {
		fmt.Println("Resolved Findings:")
		for _, f := range d.Resolved {
			fmt.Printf("  [%s] %s — %s (%s)\n", f.Severity, f.RuleID, f.Message, f.File)
		}
		fmt.Println()
	}
}
