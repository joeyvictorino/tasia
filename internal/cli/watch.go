package cli

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/config"
	"github.com/joeyvictorino/tasia/internal/ignore"
	"github.com/joeyvictorino/tasia/internal/report"
	"github.com/joeyvictorino/tasia/internal/rules"
)

func runWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	failOn := fs.String("fail-on", "", "fail level: critical, high, medium, low")
	interval := fs.Duration("interval", 2*time.Second, "polling interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateFailOn(*failOn); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	fmt.Printf("Watching %s... press Ctrl+C to stop\n\n", absPath)

	prev := snapshotModTimes(absPath)
	scanAndPrint(absPath, *failOn)

	for {
		select {
		case <-sigCh:
			fmt.Println("\nStopped.")
			return nil
		case <-time.After(*interval):
			cur := snapshotModTimes(absPath)
			if !modTimesEqual(prev, cur) {
				prev = cur
				scanAndPrint(absPath, *failOn)
			}
		}
	}
}

// ScanResult holds the outcome of one scan pass (exported for testing).
type ScanResult struct {
	Findings []rules.Finding
	Decision string
	Risk     string
	Err      error
}

// RunScan performs a single scan of the given path and returns the result.
func RunScan(absPath, failOn string) ScanResult {
	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return ScanResult{Err: err}
	}
	if len(collected.ParseErrors) > 0 {
		return ScanResult{Err: fmt.Errorf("parse errors in %d file(s)", len(collected.ParseErrors))}
	}

	findings := rules.Evaluate(collected)

	if pol, err := ignore.Load(absPath); err == nil {
		pol.AddInline(ignore.ScanInline(absPath))
		findings = filterFindings(findings, pol)
	}

	if cfg, err := config.Load(absPath); err == nil {
		findings = applySeverityOverrides(findings, cfg)
	}

	decision, risk := report.Decide(findings, failOn, false)
	return ScanResult{
		Findings: findings,
		Decision: decision,
		Risk:     risk,
	}
}

func scanAndPrint(absPath, failOn string) {
	ts := time.Now().Format("15:04:05")
	result := RunScan(absPath, failOn)
	if result.Err != nil {
		fmt.Printf("[%s] Error: %v\n", ts, result.Err)
		return
	}
	fmt.Printf("[%s] %d finding(s) — Decision: %s (Risk: %s)\n",
		ts, len(result.Findings), result.Decision, result.Risk)
	for _, f := range result.Findings {
		fmt.Printf("  [%s] %s:%d %s\n", f.Severity, f.File, f.Line, f.Title)
	}
	fmt.Println()
}

func snapshotModTimes(root string) map[string]time.Time {
	m := make(map[string]time.Time)
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".tasia" || info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		m[rel] = info.ModTime()
		return nil
	})
	return m
}

func modTimesEqual(a, b map[string]time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || !v.Equal(bv) {
			return false
		}
	}
	return true
}
