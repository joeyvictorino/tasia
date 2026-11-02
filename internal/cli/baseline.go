package cli

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/joeyvictorino/tasia/internal/rules"
)

type FindingSummary struct {
	Hash     string `json:"hash"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

type BaselineSnapshot struct {
	Version       string           `json:"version"`
	Timestamp     string           `json:"timestamp"`
	Path          string           `json:"path"`
	FindingHashes []string         `json:"finding_hashes"`
	Findings      []FindingSummary `json:"findings"`
}

type BaselineComparison struct {
	New       []FindingSummary `json:"new"`
	Resolved  []FindingSummary `json:"resolved"`
	Unchanged []FindingSummary `json:"unchanged"`
}

func hashFinding(f rules.Finding) string {
	data := fmt.Sprintf("%s:%s:%s:%d", f.ID, f.Severity, f.File, f.Line)
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h[:8])
}

func findingsToSummaries(findings []rules.Finding) []FindingSummary {
	summaries := make([]FindingSummary, len(findings))
	for i, f := range findings {
		summaries[i] = FindingSummary{
			Hash:     hashFinding(f),
			RuleID:   f.ID,
			Severity: string(f.Severity),
			File:     f.File,
			Line:     f.Line,
		}
	}
	return summaries
}

func createBaseline(path string) BaselineSnapshot {
	findings := scanDir(path)
	summaries := findingsToSummaries(findings)
	hashes := make([]string, len(summaries))
	for i, s := range summaries {
		hashes[i] = s.Hash
	}
	return BaselineSnapshot{
		Version:       versionString(),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Path:          path,
		FindingHashes: hashes,
		Findings:      summaries,
	}
}

func compareBaseline(baseline BaselineSnapshot, current []rules.Finding) BaselineComparison {
	currentSummaries := findingsToSummaries(current)
	baselineSet := map[string]FindingSummary{}
	for _, f := range baseline.Findings {
		baselineSet[f.Hash] = f
	}
	currentSet := map[string]FindingSummary{}
	for _, f := range currentSummaries {
		currentSet[f.Hash] = f
	}

	var comp BaselineComparison
	for _, f := range currentSummaries {
		if _, ok := baselineSet[f.Hash]; ok {
			comp.Unchanged = append(comp.Unchanged, f)
		} else {
			comp.New = append(comp.New, f)
		}
	}
	for _, f := range baseline.Findings {
		if _, ok := currentSet[f.Hash]; !ok {
			comp.Resolved = append(comp.Resolved, f)
		}
	}
	return comp
}

func runBaseline(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: tasia baseline <create|compare|update> [flags]")
		return fmt.Errorf("subcommand required")
	}

	switch args[0] {
	case "create":
		return baselineCreate(args[1:])
	case "compare":
		return baselineCompare(args[1:])
	case "update":
		return baselineUpdate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "tasia baseline: unknown subcommand %q\n", args[0])
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func baselineCreate(args []string) error {
	fs := flag.NewFlagSet("baseline create", flag.ContinueOnError)
	path := fs.String("path", ".", "directory to scan")
	output := fs.String("output", "tasia-baseline.json", "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	snap := createBaseline(absPath)

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(*output, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Created baseline with %d findings: %s\n", len(snap.Findings), *output)
	return nil
}

func baselineCompare(args []string) error {
	fs := flag.NewFlagSet("baseline compare", flag.ContinueOnError)
	baselinePath := fs.String("baseline", "", "baseline JSON file (required)")
	path := fs.String("path", ".", "directory to scan")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *baselinePath == "" {
		fmt.Fprintln(os.Stderr, "tasia baseline compare: --baseline is required")
		return fmt.Errorf("--baseline is required")
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(*baselinePath)
	if err != nil {
		return fmt.Errorf("reading baseline: %w", err)
	}
	var snap BaselineSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("parsing baseline: %w", err)
	}

	current := scanDir(absPath)
	comp := compareBaseline(snap, current)

	switch *format {
	case "json":
		out, err := json.MarshalIndent(comp, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	default:
		fmt.Printf("Baseline comparison:\n")
		fmt.Printf("  New findings:      %d\n", len(comp.New))
		fmt.Printf("  Resolved findings: %d\n", len(comp.Resolved))
		fmt.Printf("  Unchanged:         %d\n", len(comp.Unchanged))
		if len(comp.New) > 0 {
			fmt.Println("\nNew findings:")
			for _, f := range comp.New {
				fmt.Printf("  [%s] %s at %s:%d\n", f.Severity, f.RuleID, f.File, f.Line)
			}
		}
		if len(comp.Resolved) > 0 {
			fmt.Println("\nResolved findings:")
			for _, f := range comp.Resolved {
				fmt.Printf("  [%s] %s at %s:%d\n", f.Severity, f.RuleID, f.File, f.Line)
			}
		}
	}
	return nil
}

func baselineUpdate(args []string) error {
	fs := flag.NewFlagSet("baseline update", flag.ContinueOnError)
	baselinePath := fs.String("baseline", "", "baseline JSON file to update (required)")
	path := fs.String("path", ".", "directory to scan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *baselinePath == "" {
		fmt.Fprintln(os.Stderr, "tasia baseline update: --baseline is required")
		return fmt.Errorf("--baseline is required")
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	snap := createBaseline(absPath)

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(*baselinePath, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Updated baseline with %d findings: %s\n", len(snap.Findings), *baselinePath)
	return nil
}
