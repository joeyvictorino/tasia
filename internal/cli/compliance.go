package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/joeyvictorino/tasia/internal/compliance"
	"github.com/joeyvictorino/tasia/internal/rules"
)

type complianceControlResult struct {
	ControlID string `json:"control_id"`
	Name      string `json:"name"`
	Findings  int    `json:"findings"`
}

type complianceFrameworkResult struct {
	Framework string                    `json:"framework"`
	Controls  []complianceControlResult `json:"controls"`
	Total     int                       `json:"total_findings"`
}

type complianceResult struct {
	Path       string                      `json:"path"`
	Frameworks []complianceFrameworkResult  `json:"frameworks"`
	Unmapped   int                         `json:"unmapped_findings"`
	Total      int                         `json:"total_findings"`
}

func buildComplianceResult(absPath string, findings []rules.Finding, framework string) complianceResult {
	idx := compliance.MappingIndex()

	type ctrlKey struct {
		fw, id string
	}
	ctrlCounts := map[ctrlKey]int{}
	ctrlNames := map[ctrlKey]string{}
	mapped := map[int]bool{}

	for i, f := range findings {
		if ctrls, ok := idx[f.ID]; ok {
			for _, c := range ctrls {
				if framework != "all" && c.Framework != framework {
					continue
				}
				k := ctrlKey{c.Framework, c.ControlID}
				ctrlCounts[k]++
				ctrlNames[k] = c.Name
				mapped[i] = true
			}
		}
	}

	fwSet := map[string]bool{}
	for k := range ctrlCounts {
		fwSet[k.fw] = true
	}
	fwNames := make([]string, 0, len(fwSet))
	for fw := range fwSet {
		fwNames = append(fwNames, fw)
	}
	sort.Strings(fwNames)

	var frameworks []complianceFrameworkResult
	for _, fw := range fwNames {
		var controls []complianceControlResult
		fwTotal := 0
		for k, count := range ctrlCounts {
			if k.fw != fw {
				continue
			}
			controls = append(controls, complianceControlResult{
				ControlID: k.id,
				Name:      ctrlNames[k],
				Findings:  count,
			})
			fwTotal += count
		}
		sort.Slice(controls, func(i, j int) bool {
			return controls[i].ControlID < controls[j].ControlID
		})
		frameworks = append(frameworks, complianceFrameworkResult{
			Framework: fw,
			Controls:  controls,
			Total:     fwTotal,
		})
	}

	unmapped := 0
	if framework == "all" {
		for i := range findings {
			if !mapped[i] {
				unmapped++
			}
		}
	}

	return complianceResult{
		Path:       absPath,
		Frameworks: frameworks,
		Unmapped:   unmapped,
		Total:      len(findings),
	}
}

func printComplianceText(r complianceResult) {
	fmt.Printf("Compliance Mapping (%d findings)\n\n", r.Total)
	for _, fw := range r.Frameworks {
		fmt.Printf("  %s (%d control hits)\n", fw.Framework, fw.Total)
		for _, c := range fw.Controls {
			fmt.Printf("    %-12s %-45s %d findings\n", c.ControlID, c.Name, c.Findings)
		}
		fmt.Println()
	}
	if r.Unmapped > 0 {
		fmt.Printf("  Unmapped findings: %d\n", r.Unmapped)
	}
}

func runCompliance(args []string) error {
	fs := flag.NewFlagSet("compliance", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	framework := fs.String("framework", "all", "framework filter: all, SOC2, NIST-AI-RMF, OWASP-LLM-Top10")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var findings []rules.Finding
	if *recursive {
		findings = scanRecursive(absPath)
	} else {
		findings = scanDir(absPath)
	}

	result := buildComplianceResult(absPath, findings, *framework)

	switch *format {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		printComplianceText(result)
	}
	return nil
}
