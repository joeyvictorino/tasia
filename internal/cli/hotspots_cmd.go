package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/rules"
)

type hotspotEntry struct {
	File         string         `json:"file"`
	FindingCount int            `json:"finding_count"`
	BySeverity   map[string]int `json:"by_severity"`
	ByCategory   map[string]int `json:"by_category"`
	RiskScore    float64        `json:"risk_score"`
}

type hotspotResult struct {
	TotalFiles    int            `json:"total_files"`
	TotalFindings int            `json:"total_findings"`
	Hotspots      []hotspotEntry `json:"hotspots"`
}

func runHotspots(args []string) error {
	fs := flag.NewFlagSet("hotspots", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	top := fs.Int("top", 10, "number of hotspots to show")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return fmt.Errorf("collecting: %w", err)
	}

	rawFindings := rules.Evaluate(collected)
	result := buildHotspots(rawFindings, absPath, *top)

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	default:
		fmt.Print(formatHotspotsText(result))
		return nil
	}
}

var severityWeights = map[string]float64{
	"CRITICAL": 10.0,
	"HIGH":     5.0,
	"MEDIUM":   2.0,
	"LOW":      1.0,
}

func buildHotspots(findings []rules.Finding, basePath string, top int) hotspotResult {
	type fileAgg struct {
		bySeverity map[string]int
		byCategory map[string]int
		count      int
	}

	agg := map[string]*fileAgg{}

	for _, f := range findings {
		rel := f.File
		if strings.HasPrefix(rel, basePath) {
			rel, _ = filepath.Rel(basePath, rel)
		}
		if agg[rel] == nil {
			agg[rel] = &fileAgg{
				bySeverity: map[string]int{},
				byCategory: map[string]int{},
			}
		}
		a := agg[rel]
		a.count++
		sev := strings.ToUpper(string(f.Severity))
		a.bySeverity[sev]++
		cat := categoryFromRuleID(f.ID)
		a.byCategory[cat]++
	}

	var entries []hotspotEntry
	for file, a := range agg {
		score := 0.0
		for sev, cnt := range a.bySeverity {
			w := severityWeights[sev]
			if w == 0 {
				w = 1.0
			}
			score += w * float64(cnt)
		}
		entries = append(entries, hotspotEntry{
			File:         file,
			FindingCount: a.count,
			BySeverity:   a.bySeverity,
			ByCategory:   a.byCategory,
			RiskScore:    score,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].RiskScore > entries[j].RiskScore
	})

	if top > 0 && len(entries) > top {
		entries = entries[:top]
	}

	return hotspotResult{
		TotalFiles:    len(agg),
		TotalFindings: len(findings),
		Hotspots:      entries,
	}
}

func categoryFromRuleID(id string) string {
	parts := strings.SplitN(id, "_", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return "other"
}

func formatHotspotsText(r hotspotResult) string {
	var b strings.Builder
	b.WriteString("Finding Hotspots\n")
	b.WriteString("========================================\n")
	fmt.Fprintf(&b, "Total files with findings: %d\n", r.TotalFiles)
	fmt.Fprintf(&b, "Total findings: %d\n\n", r.TotalFindings)

	if len(r.Hotspots) > 0 {
		fmt.Fprintf(&b, "  %-40s %6s %8s %8s\n", "FILE", "COUNT", "SCORE", "SEVS")
		b.WriteString("  " + strings.Repeat("-", 66) + "\n")
		for _, h := range r.Hotspots {
			sevs := formatSevCounts(h.BySeverity)
			fmt.Fprintf(&b, "  %-40s %6d %8.1f  %s\n",
				truncPath(h.File, 40), h.FindingCount, h.RiskScore, sevs)
		}
	}
	return b.String()
}

func truncPath(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max+3:]
}

func formatSevCounts(m map[string]int) string {
	var parts []string
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if cnt, ok := m[sev]; ok && cnt > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", strings.ToLower(sev[:1]), cnt))
		}
	}
	return strings.Join(parts, " ")
}
