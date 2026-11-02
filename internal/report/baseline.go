package report

import (
	"encoding/json"
	"os"

	"github.com/joeyvictorino/tasia/internal/rules"
)

type baselineKey struct {
	RuleID string
	File   string
	Line   int
}

// LoadBaseline reads a SARIF file and extracts finding fingerprints for
// baseline comparison. Returns a set of (ruleID, file, line) keys.
func LoadBaseline(path string) (map[baselineKey]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var sarif struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &sarif); err != nil {
		return nil, err
	}

	keys := map[baselineKey]bool{}
	for _, run := range sarif.Runs {
		for _, result := range run.Results {
			for _, loc := range result.Locations {
				keys[baselineKey{
					RuleID: result.RuleID,
					File:   loc.PhysicalLocation.ArtifactLocation.URI,
					Line:   loc.PhysicalLocation.Region.StartLine,
				}] = true
			}
		}
	}
	return keys, nil
}

// FilterBaseline removes findings already present in the baseline set.
// Returns only new or changed findings.
func FilterBaseline(findings []rules.Finding, baseline map[baselineKey]bool) (kept []rules.Finding, suppressed int) {
	for _, f := range findings {
		k := baselineKey{RuleID: f.ID, File: f.File, Line: f.Line}
		if baseline[k] {
			suppressed++
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}
