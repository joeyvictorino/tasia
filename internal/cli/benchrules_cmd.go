package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/config"
	"github.com/joeyvictorino/tasia/internal/ignore"
	"github.com/joeyvictorino/tasia/internal/rules"
)

type ruleTiming struct {
	Category     string  `json:"category"`
	FindingCount int     `json:"finding_count"`
	RuleIDs      []string `json:"rule_ids"`
}

type benchRulesResult struct {
	Path          string            `json:"path"`
	Iterations    int               `json:"iterations"`
	CollectMs     float64           `json:"collect_ms"`
	EvaluateMs    float64           `json:"evaluate_ms"`
	TotalMs       float64           `json:"total_ms"`
	FindingsTotal int               `json:"findings_total"`
	RulesTotal    int               `json:"rules_total"`
	Categories    []ruleTiming      `json:"categories"`
	BySeverity    map[string]int    `json:"by_severity"`
	Slowest       string            `json:"slowest_phase"`
}

func runBenchmarkRules(args []string) error {
	fs := flag.NewFlagSet("tasia benchmark-rules", flag.ContinueOnError)
	path := fs.String("path", ".", "directory to benchmark")
	format := fs.String("format", "text", "output format: text or json")
	iterations := fs.Int("iterations", 3, "number of iterations (results averaged)")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var totalCollect, totalEvaluate, totalAll float64
	var lastFindings []rules.Finding

	for i := 0; i < *iterations; i++ {
		t0 := time.Now()

		var findings []rules.Finding
		if *recursive {
			findings = scanRecursive(absPath)
			elapsed := time.Since(t0)
			totalAll += float64(elapsed.Microseconds()) / 1000.0
		} else {
			tc := time.Now()
			collected, err := collect.WalkAndCollect(absPath)
			collectDur := time.Since(tc)
			if err != nil {
				return fmt.Errorf("collecting: %w", err)
			}
			if len(collected.ParseErrors) > 0 {
				return fmt.Errorf("parse errors in config files; cannot benchmark")
			}
			totalCollect += float64(collectDur.Microseconds()) / 1000.0

			te := time.Now()
			findings = rules.Evaluate(collected)
			evalDur := time.Since(te)
			totalEvaluate += float64(evalDur.Microseconds()) / 1000.0

			if pol, err := ignore.Load(absPath); err == nil {
				pol.AddInline(ignore.ScanInline(absPath))
				findings = filterFindings(findings, pol)
			}
			if cfg, err := config.Load(absPath); err == nil {
				findings = applySeverityOverrides(findings, cfg)
			}

			totalAll += float64(time.Since(t0).Microseconds()) / 1000.0
		}
		lastFindings = findings
	}

	n := float64(*iterations)
	avgCollect := totalCollect / n
	avgEvaluate := totalEvaluate / n
	avgTotal := totalAll / n

	catalogMap := rules.CatalogMap()
	catFindings := map[string][]string{}
	catCount := map[string]int{}
	bySeverity := map[string]int{}

	for _, f := range lastFindings {
		bySeverity[string(f.Severity)]++
		cat := "unknown"
		if info, ok := catalogMap[f.ID]; ok {
			cat = info.Category
		}
		catCount[cat]++
		if !containsStr(catFindings[cat], f.ID) {
			catFindings[cat] = append(catFindings[cat], f.ID)
		}
	}

	var categories []ruleTiming
	for cat, count := range catCount {
		categories = append(categories, ruleTiming{
			Category:     cat,
			FindingCount: count,
			RuleIDs:      catFindings[cat],
		})
	}
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].FindingCount > categories[j].FindingCount
	})

	slowest := "evaluate"
	if avgCollect > avgEvaluate {
		slowest = "collect"
	}

	result := benchRulesResult{
		Path:          absPath,
		Iterations:    *iterations,
		CollectMs:     avgCollect,
		EvaluateMs:    avgEvaluate,
		TotalMs:       avgTotal,
		FindingsTotal: len(lastFindings),
		RulesTotal:    len(rules.Catalog()),
		Categories:    categories,
		BySeverity:    bySeverity,
		Slowest:       slowest,
	}

	switch *format {
	case "json":
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	default:
		printBenchRulesText(result)
	}
	return nil
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func printBenchRulesText(r benchRulesResult) {
	fmt.Println("Tasia Rule Benchmark")
	fmt.Println("========================================")
	fmt.Printf("Path:       %s\n", r.Path)
	fmt.Printf("Iterations: %d (averaged)\n", r.Iterations)
	fmt.Printf("Rules:      %d\n", r.RulesTotal)
	fmt.Printf("Findings:   %d\n\n", r.FindingsTotal)

	fmt.Println("Phase Timing")
	fmt.Println("----------------------------------------")
	fmt.Printf("  %-15s %10.2f ms\n", "Collect", r.CollectMs)
	fmt.Printf("  %-15s %10.2f ms\n", "Evaluate", r.EvaluateMs)
	fmt.Printf("  %-15s %10.2f ms\n", "Total", r.TotalMs)
	fmt.Printf("  Bottleneck:    %s\n\n", r.Slowest)

	if len(r.Categories) > 0 {
		fmt.Println("Findings by Category")
		fmt.Println("----------------------------------------")
		for _, c := range r.Categories {
			fmt.Printf("  %-18s %4d findings  (%d rules: %s)\n",
				c.Category, c.FindingCount, len(c.RuleIDs), joinMax(c.RuleIDs, 3))
		}
		fmt.Println()
	}

	if len(r.BySeverity) > 0 {
		fmt.Println("Findings by Severity")
		fmt.Println("----------------------------------------")
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
			if count, ok := r.BySeverity[sev]; ok && count > 0 {
				fmt.Printf("  %-10s %d\n", sev, count)
			}
		}
	}
}

func joinMax(ss []string, max int) string {
	if len(ss) <= max {
		return joinStrings(ss)
	}
	out := joinStrings(ss[:max])
	return fmt.Sprintf("%s +%d more", out, len(ss)-max)
}

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}
