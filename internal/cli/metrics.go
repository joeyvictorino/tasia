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

type metricsJSON struct {
	Decision string      `json:"decision"`
	Risk     string      `json:"risk"`
	Summary  *metricsSummary `json:"summary"`
	Findings []metricsF  `json:"findings"`
}

type metricsSummary struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
}

type metricsF struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	File     string `json:"file"`
}

type metricsPoint struct {
	Source   string         `json:"source"`
	Decision string        `json:"decision"`
	Risk     string         `json:"risk"`
	Total    int            `json:"total"`
	BySev    map[string]int `json:"by_severity"`
	ByRule   map[string]int `json:"by_rule"`
}

type metricsResult struct {
	Points    []metricsPoint `json:"points"`
	TotalRuns int            `json:"total_runs"`
	PassRate  float64        `json:"pass_rate"`
	AvgScore  int            `json:"avg_score"`
	SevTrend  map[string][]int `json:"severity_trend"`
	TopRules  []ruleCount    `json:"top_rules"`
}

type ruleCount struct {
	ID    string `json:"id"`
	Count int    `json:"count"`
}

func runMetrics(args []string) error {
	fs := flag.NewFlagSet("metrics", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory containing scan JSON files (required)")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("--dir is required")
	}

	entries, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	if len(files) == 0 {
		return fmt.Errorf("no .json files found in %s", *dir)
	}

	var points []metricsPoint
	sevTrend := make(map[string][]int)
	allRules := make(map[string]int)
	passCount := 0
	totalScore := 0

	for _, fname := range files {
		data, err := os.ReadFile(filepath.Join(*dir, fname))
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", fname, err)
			continue
		}
		var scan metricsJSON
		if err := json.Unmarshal(data, &scan); err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", fname, err)
			continue
		}

		bySev := make(map[string]int)
		byRule := make(map[string]int)
		for _, f := range scan.Findings {
			sev := f.Severity
			if sev == "" {
				sev = "UNKNOWN"
			}
			bySev[sev]++
			byRule[f.ID]++
			allRules[f.ID]++
		}

		if scan.Summary != nil && scan.Summary.BySeverity != nil {
			for k, v := range scan.Summary.BySeverity {
				if _, ok := bySev[k]; !ok {
					bySev[k] = v
				}
			}
		}

		total := len(scan.Findings)
		if scan.Summary != nil && scan.Summary.TotalFindings > total {
			total = scan.Summary.TotalFindings
		}

		pt := metricsPoint{
			Source:   fname,
			Decision: scan.Decision,
			Risk:     scan.Risk,
			Total:    total,
			BySev:    bySev,
			ByRule:   byRule,
		}
		points = append(points, pt)

		if strings.EqualFold(scan.Decision, "PASS") {
			passCount++
		}

		score := computeScore(bySev)
		totalScore += score

		for s, c := range bySev {
			sevTrend[s] = append(sevTrend[s], c)
		}
	}

	var topRules []ruleCount
	for id, c := range allRules {
		topRules = append(topRules, ruleCount{ID: id, Count: c})
	}
	sort.Slice(topRules, func(i, j int) bool {
		return topRules[i].Count > topRules[j].Count
	})
	if len(topRules) > 10 {
		topRules = topRules[:10]
	}

	passRate := 0.0
	avgScore := 0
	if len(points) > 0 {
		passRate = float64(passCount) / float64(len(points)) * 100
		avgScore = totalScore / len(points)
	}

	result := metricsResult{
		Points:    points,
		TotalRuns: len(points),
		PassRate:  passRate,
		AvgScore:  avgScore,
		SevTrend:  sevTrend,
		TopRules:  topRules,
	}

	switch *format {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		printMetrics(result)
	}
	return nil
}

func printMetrics(r metricsResult) {
	fmt.Printf("Security Metrics (%d runs)\n", r.TotalRuns)
	fmt.Printf("Pass rate: %.1f%%\n", r.PassRate)
	fmt.Printf("Avg score: %d/100\n\n", r.AvgScore)

	fmt.Printf("%-30s %8s %8s %s\n", "Run", "Total", "Decision", "Breakdown")
	fmt.Printf("%s\n", strings.Repeat("-", 72))
	for _, pt := range r.Points {
		parts := formatSevBreakdown(pt.BySev)
		fmt.Printf("%-30s %8d %8s %s\n", pt.Source, pt.Total, pt.Decision, parts)
	}

	if len(r.SevTrend) > 0 {
		fmt.Printf("\nSeverity trends:\n")
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
			if vals, ok := r.SevTrend[sev]; ok {
				fmt.Printf("  %-10s %v\n", sev, vals)
			}
		}
	}

	if len(r.TopRules) > 0 {
		fmt.Printf("\nTop rules:\n")
		for _, rc := range r.TopRules {
			fmt.Printf("  %-40s %d\n", rc.ID, rc.Count)
		}
	}
}

func formatSevBreakdown(m map[string]int) string {
	var parts []string
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if c, ok := m[sev]; ok && c > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", strings.ToLower(sev), c))
		}
	}
	return strings.Join(parts, " ")
}
