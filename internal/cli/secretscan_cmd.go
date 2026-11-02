package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/secretscan"
)

func runSecretsScan(args []string) error {
	fs := flag.NewFlagSet("secrets-scan", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	filterType := fs.String("type", "", "filter by secret type (api_key, password, token, certificate, connection_string)")
	minSeverity := fs.String("min-severity", "", "minimum severity to report (critical, high, medium, low)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	result, err := secretscan.ScanDirectory(absPath, *recursive)
	if err != nil {
		return err
	}

	if *filterType != "" || *minSeverity != "" {
		result = filterResults(result, *filterType, *minSeverity)
	}

	switch *format {
	case "json":
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	default:
		fmt.Print(secretscan.FormatText(result))
	}
	return nil
}

func filterResults(r secretscan.ScanResult, filterType, minSeverity string) secretscan.ScanResult {
	sevRank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	minRank := sevRank[minSeverity]

	var filtered []secretscan.SecretFinding
	for _, f := range r.Findings {
		if filterType != "" && f.Type != filterType {
			continue
		}
		if minSeverity != "" && sevRank[f.Severity] < minRank {
			continue
		}
		filtered = append(filtered, f)
	}

	r.Findings = filtered
	r.SecretsFound = len(filtered)
	r.BySeverity = map[string]int{}
	r.ByType = map[string]int{}
	for _, f := range filtered {
		r.BySeverity[f.Severity]++
		r.ByType[f.Type]++
	}
	return r
}
