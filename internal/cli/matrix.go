package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/config"
	"github.com/joeyvictorino/tasia/internal/ignore"
	"github.com/joeyvictorino/tasia/internal/rules"
)

type matrixCell struct {
	Severity   string   `json:"severity"`
	Likelihood string   `json:"likelihood"`
	Count      int      `json:"count"`
	RuleIDs    []string `json:"rule_ids"`
	Risk       string   `json:"risk"`
}

type matrixResult struct {
	Path       string       `json:"path"`
	TotalCells int          `json:"total_cells"`
	Critical   int          `json:"critical_risk"`
	High       int          `json:"high_risk"`
	Medium     int          `json:"medium_risk"`
	Low        int          `json:"low_risk"`
	Cells      []matrixCell `json:"cells"`
}

func runMatrix(args []string) error {
	fs := flag.NewFlagSet("matrix", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
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

	findings := rules.Evaluate(collected)

	if pol, err := ignore.Load(absPath); err == nil {
		pol.AddInline(ignore.ScanInline(absPath))
		findings = filterFindings(findings, pol)
	}

	if cfg, err := config.Load(absPath); err == nil {
		findings = applySeverityOverrides(findings, cfg)
	}

	cellMap := make(map[string]*matrixCell)
	for _, f := range findings {
		sev := string(f.Severity)
		likelihood := estimateLikelihood(f)
		key := sev + "|" + likelihood
		c, ok := cellMap[key]
		if !ok {
			c = &matrixCell{
				Severity:   sev,
				Likelihood: likelihood,
				Risk:       computeRiskLevel(sev, likelihood),
			}
			cellMap[key] = c
		}
		c.Count++
		found := false
		for _, r := range c.RuleIDs {
			if r == f.ID {
				found = true
				break
			}
		}
		if !found {
			c.RuleIDs = append(c.RuleIDs, f.ID)
		}
	}

	cells := make([]matrixCell, 0, len(cellMap))
	for _, c := range cellMap {
		sort.Strings(c.RuleIDs)
		cells = append(cells, *c)
	}
	sort.Slice(cells, func(i, j int) bool {
		ri := riskOrdinal(cells[i].Risk)
		rj := riskOrdinal(cells[j].Risk)
		if ri != rj {
			return ri > rj
		}
		return cells[i].Count > cells[j].Count
	})

	critical, high, medium, low := 0, 0, 0, 0
	for _, c := range cells {
		switch c.Risk {
		case "critical":
			critical += c.Count
		case "high":
			high += c.Count
		case "medium":
			medium += c.Count
		case "low":
			low += c.Count
		}
	}

	result := matrixResult{
		Path:       absPath,
		TotalCells: len(cells),
		Critical:   critical,
		High:       high,
		Medium:     medium,
		Low:        low,
		Cells:      cells,
	}

	switch *format {
	case "json":
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	default:
		printMatrix(result)
	}
	return nil
}

func estimateLikelihood(f rules.Finding) string {
	id := strings.ToLower(f.ID)
	switch {
	case strings.Contains(id, "docker_sock") || strings.Contains(id, "privileged") || strings.Contains(id, "secret"):
		return "high"
	case strings.Contains(id, "network") || strings.Contains(id, "port") || strings.Contains(id, "auth"):
		return "medium"
	default:
		return "low"
	}
}

func computeRiskLevel(severity, likelihood string) string {
	so := sevOrdinal(severity)
	lo := likelihoodOrdinal(likelihood)
	score := so * lo
	switch {
	case score >= 9:
		return "critical"
	case score >= 6:
		return "high"
	case score >= 3:
		return "medium"
	default:
		return "low"
	}
}

func sevOrdinal(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 1
	}
}

func likelihoodOrdinal(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 1
	}
}

func riskOrdinal(s string) int {
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

func printMatrix(r matrixResult) {
	fmt.Printf("Risk Matrix (%d cells, %d critical, %d high, %d medium, %d low)\n\n",
		r.TotalCells, r.Critical, r.High, r.Medium, r.Low)
	fmt.Printf("  %-12s %-12s %-10s %5s  %s\n", "Severity", "Likelihood", "Risk", "Count", "Rules")
	fmt.Printf("  %s\n", strings.Repeat("-", 70))
	for _, c := range r.Cells {
		ruleStr := strings.Join(c.RuleIDs, ", ")
		if len(ruleStr) > 30 {
			ruleStr = ruleStr[:27] + "..."
		}
		fmt.Printf("  %-12s %-12s %-10s %5d  %s\n", c.Severity, c.Likelihood, c.Risk, c.Count, ruleStr)
	}
}
