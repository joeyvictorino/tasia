package riskmatrix

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/rules"
)

type MatrixCell struct {
	Severity   string   `json:"severity"`
	Likelihood string   `json:"likelihood"`
	Count      int      `json:"count"`
	RuleIDs    []string `json:"rule_ids"`
	RiskLevel  string   `json:"risk_level"`
}

type RiskMatrix struct {
	Cells     []MatrixCell `json:"cells"`
	TotalRisk float64      `json:"total_risk"`
	TopRisks  []MatrixCell `json:"top_risks"`
}

var severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
var likelihoods = []string{"certain", "likely", "possible", "unlikely", "rare"}

var likelihoodByCategory = map[string]string{
	"no_auth":              "likely",
	"privileged":           "possible",
	"env_hardcoded":        "likely",
	"network_mode_host":    "possible",
	"sensitive_port":       "possible",
	"writable_mount":       "possible",
	"agent_auto_approve":   "likely",
	"agent_no_sandbox":     "likely",
	"restart_always":       "possible",
	"no_network_policy":    "likely",
	"user_root":            "possible",
	"expose_internal":      "unlikely",
	"tf_":                  "possible",
	"helm_":                "possible",
	"kube_":                "possible",
	"docker_":              "possible",
	"caddy_":               "unlikely",
	"nginx_":               "unlikely",
}

var riskLookup = map[string]map[string]string{
	"CRITICAL": {"certain": "extreme", "likely": "extreme", "possible": "high", "unlikely": "high", "rare": "medium"},
	"HIGH":     {"certain": "extreme", "likely": "high", "possible": "high", "unlikely": "medium", "rare": "medium"},
	"MEDIUM":   {"certain": "high", "likely": "medium", "possible": "medium", "unlikely": "low", "rare": "low"},
	"LOW":      {"certain": "medium", "likely": "low", "possible": "low", "unlikely": "low", "rare": "low"},
}

var riskScores = map[string]float64{
	"extreme": 4.0,
	"high":    3.0,
	"medium":  2.0,
	"low":     1.0,
}

func BuildMatrix(findings []rules.Finding) RiskMatrix {
	type cellKey struct {
		sev  string
		like string
	}
	cellMap := map[cellKey]*MatrixCell{}

	for _, s := range severities {
		for _, l := range likelihoods {
			k := cellKey{s, l}
			cellMap[k] = &MatrixCell{
				Severity:   s,
				Likelihood: l,
				RiskLevel:  riskLookup[s][l],
			}
		}
	}

	for _, f := range findings {
		like := assignLikelihood(f.ID)
		sev := string(f.Severity)
		k := cellKey{sev, like}
		cell := cellMap[k]
		if cell == nil {
			continue
		}
		cell.Count++
		found := false
		for _, id := range cell.RuleIDs {
			if id == f.ID {
				found = true
				break
			}
		}
		if !found {
			cell.RuleIDs = append(cell.RuleIDs, f.ID)
		}
	}

	var cells []MatrixCell
	totalRisk := 0.0
	for _, s := range severities {
		for _, l := range likelihoods {
			c := cellMap[cellKey{s, l}]
			cells = append(cells, *c)
			totalRisk += float64(c.Count) * riskScores[c.RiskLevel]
		}
	}

	sort.Slice(cells, func(i, j int) bool {
		return riskScores[cells[i].RiskLevel]*float64(cells[i].Count) > riskScores[cells[j].RiskLevel]*float64(cells[j].Count)
	})

	var topRisks []MatrixCell
	for _, c := range cells {
		if c.Count > 0 && len(topRisks) < 5 {
			topRisks = append(topRisks, c)
		}
	}

	return RiskMatrix{
		Cells:     cells,
		TotalRisk: totalRisk,
		TopRisks:  topRisks,
	}
}

func assignLikelihood(ruleID string) string {
	for prefix, like := range likelihoodByCategory {
		if strings.HasPrefix(ruleID, prefix) {
			return like
		}
	}
	return "possible"
}

func FormatText(m RiskMatrix) string {
	var sb strings.Builder
	sb.WriteString("Risk Matrix (Severity × Likelihood)\n\n")

	grid := map[string]map[string]int{}
	for _, s := range severities {
		grid[s] = map[string]int{}
	}
	for _, c := range m.Cells {
		grid[c.Severity][c.Likelihood] = c.Count
	}

	sb.WriteString(fmt.Sprintf("  %-10s", ""))
	for _, l := range likelihoods {
		sb.WriteString(fmt.Sprintf(" %-10s", l))
	}
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("  %-10s", strings.Repeat("-", 10)))
	for range likelihoods {
		sb.WriteString(fmt.Sprintf(" %-10s", strings.Repeat("-", 10)))
	}
	sb.WriteString("\n")

	for _, s := range severities {
		sb.WriteString(fmt.Sprintf("  %-10s", s))
		for _, l := range likelihoods {
			cnt := grid[s][l]
			if cnt > 0 {
				level := riskLookup[s][l]
				sb.WriteString(fmt.Sprintf(" %-10s", fmt.Sprintf("%d[%s]", cnt, level[:1])))
			} else {
				sb.WriteString(fmt.Sprintf(" %-10s", "."))
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("\nTotal Risk Score: %.1f\n", m.TotalRisk))

	if len(m.TopRisks) > 0 {
		sb.WriteString("\nTop Risks:\n")
		for i, r := range m.TopRisks {
			sb.WriteString(fmt.Sprintf("  %d. %s × %s = %s (%d findings: %s)\n",
				i+1, r.Severity, r.Likelihood, r.RiskLevel, r.Count,
				strings.Join(r.RuleIDs, ", ")))
		}
	}

	return sb.String()
}
