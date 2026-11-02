package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/config"
	"github.com/joeyvictorino/tasia/internal/ignore"
	"github.com/joeyvictorino/tasia/internal/rules"
)

type historyRecord struct {
	Timestamp string         `json:"timestamp"`
	Decision  string         `json:"decision"`
	Total     int            `json:"total"`
	BySev     map[string]int `json:"by_severity"`
	Score     int            `json:"score"`
}

type historyData struct {
	Records []historyRecord `json:"records"`
}

func runHistory(args []string) error {
	if len(args) == 0 {
		return runHistoryList(nil)
	}
	switch args[0] {
	case "list":
		return runHistoryList(args[1:])
	case "record":
		return runHistoryRecord(args[1:])
	case "clear":
		return runHistoryClear(args[1:])
	default:
		return fmt.Errorf("unknown history subcommand: %s (use list, record, or clear)", args[0])
	}
}

func runHistoryList(args []string) error {
	fs := flag.NewFlagSet("history list", flag.ContinueOnError)
	path := fs.String("path", ".", "project directory")
	format := fs.String("format", "text", "output format: text or json")
	last := fs.Int("last", 0, "show only last N entries")
	if args != nil {
		if err := fs.Parse(args); err != nil {
			return err
		}
	}

	data, histPath, err := loadHistory(*path)
	if err != nil {
		return err
	}

	records := data.Records
	if *last > 0 && *last < len(records) {
		records = records[len(records)-*last:]
	}

	if *format == "json" {
		out := map[string]any{
			"path":    histPath,
			"records": records,
			"count":   len(records),
		}
		j, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(j))
	} else {
		fmt.Printf("Scan History (%s)\n\n", histPath)
		if len(records) == 0 {
			fmt.Println("  (no records)")
		} else {
			fmt.Printf("%-22s %8s %6s %6s\n", "Timestamp", "Decision", "Total", "Score")
			fmt.Printf("%s\n", strings.Repeat("-", 50))
			for _, r := range records {
				fmt.Printf("%-22s %8s %6d %6d\n", r.Timestamp, r.Decision, r.Total, r.Score)
			}
		}
		fmt.Printf("\nTotal: %d records\n", len(records))
	}
	return nil
}

func runHistoryRecord(args []string) error {
	fs := flag.NewFlagSet("history record", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan and record")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}
	if len(collected.ParseErrors) > 0 {
		return fmt.Errorf("parse errors in %s", absPath)
	}

	findings := rules.Evaluate(collected)

	if pol, err := ignore.Load(absPath); err == nil {
		pol.AddInline(ignore.ScanInline(absPath))
		findings = filterFindings(findings, pol)
	}
	if cfg, err := config.Load(absPath); err == nil {
		findings = applySeverityOverrides(findings, cfg)
	}

	decision, _ := report_decide(findings)

	bySev := make(map[string]int)
	for _, f := range findings {
		bySev[string(f.Severity)]++
	}

	score := computeScore(bySev)

	record := historyRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Decision:  decision,
		Total:     len(findings),
		BySev:     bySev,
		Score:     score,
	}

	data, histPath, err := loadHistory(*path)
	if err != nil {
		return err
	}

	data.Records = append(data.Records, record)

	if err := saveHistory(histPath, data); err != nil {
		return err
	}

	fmt.Printf("Recorded scan: %s (decision=%s, findings=%d, score=%d)\n", record.Timestamp, decision, len(findings), score)
	return nil
}

func runHistoryClear(args []string) error {
	fs := flag.NewFlagSet("history clear", flag.ContinueOnError)
	path := fs.String("path", ".", "project directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}
	histPath := filepath.Join(absPath, ".tasia", "history.json")
	if err := os.Remove(histPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Printf("Cleared scan history at %s\n", histPath)
	return nil
}

func report_decide(findings []rules.Finding) (string, string) {
	if len(findings) == 0 {
		return "PASS", "LOW"
	}
	for _, f := range findings {
		if f.Severity == rules.SeverityCritical || f.Severity == rules.SeverityHigh {
			return "BLOCKED", "HIGH"
		}
	}
	return "PASS", "MEDIUM"
}

func loadHistory(basePath string) (*historyData, string, error) {
	absPath, err := filepath.Abs(basePath)
	if err != nil {
		return nil, "", err
	}
	histPath := filepath.Join(absPath, ".tasia", "history.json")

	raw, err := os.ReadFile(histPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &historyData{}, histPath, nil
		}
		return nil, histPath, err
	}

	var data historyData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, histPath, fmt.Errorf("parsing %s: %w", histPath, err)
	}
	return &data, histPath, nil
}

func saveHistory(path string, data *historyData) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	j, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(j, '\n'), 0644)
}
