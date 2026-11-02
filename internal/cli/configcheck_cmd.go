package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/configcheck"
)

func runConfigCheck(args []string) error {
	fs := flag.NewFlagSet("config-check", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	failOn := fs.String("fail-on", "", "exit 1 if any conflict at or above: high, medium, low")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var results []configcheck.CheckResult
	if *recursive {
		results = checkRecursive(absPath)
	} else {
		collected, err := collect.WalkAndCollect(absPath)
		if err != nil {
			return err
		}
		results = append(results, configcheck.CheckConflicts(collected))
	}

	hasFailure := false
	for _, r := range results {
		switch *format {
		case "json":
			data, err := json.MarshalIndent(r, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(data))
		default:
			fmt.Print(configcheck.FormatText(r))
		}

		if *failOn != "" && !r.Clean {
			threshold := severityThreshold(*failOn)
			for _, c := range r.Conflicts {
				if conflictSeverityRank(c.Severity) >= threshold {
					hasFailure = true
				}
			}
		}
	}

	if hasFailure {
		fmt.Fprintln(os.Stderr, "config-check: conflicts found at or above --fail-on threshold")
		os.Exit(1)
	}
	return nil
}

func checkRecursive(root string) []configcheck.CheckResult {
	var results []configcheck.CheckResult
	entries, err := os.ReadDir(root)
	if err != nil {
		return results
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		sub := filepath.Join(root, e.Name())
		collected, err := collect.WalkAndCollect(sub)
		if err != nil {
			continue
		}
		r := configcheck.CheckConflicts(collected)
		if !r.Clean {
			results = append(results, r)
		}
	}
	if len(results) == 0 {
		collected, _ := collect.WalkAndCollect(root)
		if collected != nil {
			results = append(results, configcheck.CheckConflicts(collected))
		}
	}
	return results
}

func severityThreshold(s string) int {
	switch strings.ToLower(s) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func conflictSeverityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
