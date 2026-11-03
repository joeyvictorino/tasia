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

type BenchStats struct {
	MinMs float64 `json:"min_ms"`
	MaxMs float64 `json:"max_ms"`
	AvgMs float64 `json:"avg_ms"`
	P50Ms float64 `json:"p50_ms"`
	P95Ms float64 `json:"p95_ms"`
}

type BenchResult struct {
	Path          string     `json:"path"`
	Iterations    int        `json:"iterations"`
	WarmupRuns    int        `json:"warmup_runs"`
	FindingsCount int        `json:"findings_count"`
	RulesChecked  int        `json:"rules_checked"`
	DurationsMs   []float64  `json:"durations_ms"`
	Stats         BenchStats `json:"stats"`
}

func computeStats(durations []float64) BenchStats {
	if len(durations) == 0 {
		return BenchStats{}
	}
	sorted := make([]float64, len(durations))
	copy(sorted, durations)
	sort.Float64s(sorted)

	var sum float64
	for _, d := range sorted {
		sum += d
	}

	return BenchStats{
		MinMs: sorted[0],
		MaxMs: sorted[len(sorted)-1],
		AvgMs: sum / float64(len(sorted)),
		P50Ms: percentile(sorted, 50),
		P95Ms: percentile(sorted, 95),
	}
}

func percentile(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := float64(p) / 100.0 * float64(len(sorted)-1)
	lower := int(idx)
	if lower >= len(sorted)-1 {
		return sorted[len(sorted)-1]
	}
	frac := idx - float64(lower)
	return sorted[lower]*(1-frac) + sorted[lower+1]*frac
}

func runScan(absPath string) (int, int) {
	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return 0, 0
	}
	if len(collected.ParseErrors) > 0 {
		return 0, 0
	}
	findings := rules.Evaluate(collected)
	if pol, err := ignore.Load(absPath); err == nil {
		pol.AddInline(ignore.ScanInline(absPath))
		findings = filterFindings(findings, pol)
	}
	if cfg, err := config.Load(absPath); err == nil {
		findings = applySeverityOverrides(findings, cfg)
	}
	return len(findings), len(rules.Catalog())
}

func runBench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	path := fs.String("path", ".", "directory to benchmark")
	iterations := fs.Int("iterations", 5, "number of timed iterations")
	warmup := fs.Int("warmup", 2, "warmup iterations (not counted)")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	for i := 0; i < *warmup; i++ {
		runScan(absPath)
	}

	var durations []float64
	var findingsCount, rulesChecked int
	for i := 0; i < *iterations; i++ {
		t0 := time.Now()
		fc, rc := runScan(absPath)
		elapsed := time.Since(t0)
		durations = append(durations, float64(elapsed.Microseconds())/1000.0)
		findingsCount = fc
		rulesChecked = rc
	}

	result := BenchResult{
		Path:          absPath,
		Iterations:    *iterations,
		WarmupRuns:    *warmup,
		FindingsCount: findingsCount,
		RulesChecked:  rulesChecked,
		DurationsMs:   durations,
		Stats:         computeStats(durations),
	}

	if *format == "json" {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	} else {
		printBenchText(result)
	}
	return nil
}

func printBenchText(r BenchResult) {
	fmt.Printf("Tasia Benchmark\n")
	fmt.Printf("Path:       %s\n", r.Path)
	fmt.Printf("Iterations: %d (warmup: %d)\n", r.Iterations, r.WarmupRuns)
	fmt.Printf("Findings:   %d\n", r.FindingsCount)
	fmt.Printf("Rules:      %d\n\n", r.RulesChecked)
	fmt.Printf("%-10s %10s\n", "Metric", "Value (ms)")
	fmt.Printf("%-10s %10s\n", "------", "----------")
	fmt.Printf("%-10s %10.2f\n", "Min", r.Stats.MinMs)
	fmt.Printf("%-10s %10.2f\n", "Max", r.Stats.MaxMs)
	fmt.Printf("%-10s %10.2f\n", "Avg", r.Stats.AvgMs)
	fmt.Printf("%-10s %10.2f\n", "P50", r.Stats.P50Ms)
	fmt.Printf("%-10s %10.2f\n", "P95", r.Stats.P95Ms)
}
