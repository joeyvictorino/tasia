package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type trendPoint struct {
	File         string         `json:"file"`
	FindingCount int            `json:"finding_count"`
	BySeverity   map[string]int `json:"by_severity"`
	NewFindings  int            `json:"new_findings"`
}

type trendResult struct {
	RunCount          int          `json:"run_count"`
	TotalFindings     int          `json:"total_findings"`
	UniqueFingerprint int          `json:"unique_fingerprints"`
	Points            []trendPoint `json:"points"`
}

func runTrendsCmd(args []string) error {
	fs := flag.NewFlagSet("trends", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory containing scan result JSON files (required)")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("--dir is required")
	}

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(absDir)
	if err != nil {
		return err
	}

	var jsonFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			jsonFiles = append(jsonFiles, filepath.Join(absDir, e.Name()))
		}
	}
	sort.Strings(jsonFiles)

	if len(jsonFiles) == 0 {
		return fmt.Errorf("no JSON files found in %s", absDir)
	}

	seenFP := make(map[string]bool)
	var points []trendPoint
	totalFindings := 0

	for _, path := range jsonFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		var wrapper struct {
			Findings []struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
				Title    string `json:"title"`
				File     string `json:"file"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(data, &wrapper); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}

		point := trendPoint{
			File:       filepath.Base(path),
			BySeverity: make(map[string]int),
		}

		for _, f := range wrapper.Findings {
			point.FindingCount++
			point.BySeverity[f.Severity]++

			fp := fmt.Sprintf("%s:%s:%s", f.ID, f.Severity, f.File)
			if !seenFP[fp] {
				seenFP[fp] = true
				point.NewFindings++
			}
		}

		totalFindings += point.FindingCount
		points = append(points, point)
	}

	result := trendResult{
		RunCount:          len(points),
		TotalFindings:     totalFindings,
		UniqueFingerprint: len(seenFP),
		Points:            points,
	}

	switch *format {
	case "json":
		out, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	default:
		fmt.Printf("Tasia Finding Trends (%d runs)\n", result.RunCount)
		fmt.Printf("Total findings: %d | Unique: %d\n\n", result.TotalFindings, result.UniqueFingerprint)
		for _, p := range result.Points {
			fmt.Printf("  %-30s  %3d findings  (%d new)\n", p.File, p.FindingCount, p.NewFindings)
			sevs := make([]string, 0, len(p.BySeverity))
			for s := range p.BySeverity {
				sevs = append(sevs, s)
			}
			sort.Strings(sevs)
			parts := make([]string, 0, len(sevs))
			for _, s := range sevs {
				parts = append(parts, fmt.Sprintf("%s=%d", s, p.BySeverity[s]))
			}
			if len(parts) > 0 {
				fmt.Printf("    severity: %s\n", strings.Join(parts, ", "))
			}
		}
	}

	return nil
}
