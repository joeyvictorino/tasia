package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ProjectFindings holds scan results for a single project directory.
type ProjectFindings struct {
	Path       string   `json:"path"`
	FindingIDs []string `json:"finding_ids"`
	Count      int      `json:"count"`
	BySeverity map[string]int `json:"by_severity"`
}

// CompareResult holds the comparison of findings across multiple projects.
type CompareResult struct {
	Projects        []ProjectFindings `json:"projects"`
	CommonRules     []string          `json:"common_rules"`
	UniqueByProject map[string][]string `json:"unique_by_project"`
	TotalProjects   int               `json:"total_projects"`
}

func runCompare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	paths := fs.String("paths", "", "comma-separated list of directories to scan (required)")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *paths == "" {
		fmt.Fprintln(os.Stderr, "tasia compare: --paths is required (comma-separated directories)")
		return fmt.Errorf("--paths is required")
	}

	dirs := strings.Split(*paths, ",")
	for i := range dirs {
		dirs[i] = strings.TrimSpace(dirs[i])
	}
	if len(dirs) < 2 {
		fmt.Fprintln(os.Stderr, "tasia compare: at least 2 directories required")
		return fmt.Errorf("at least 2 directories required")
	}

	result := compareProjects(dirs)

	switch *format {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		printCompareText(result)
	}
	return nil
}

func compareProjects(dirs []string) CompareResult {
	rulesByProject := map[string]map[string]bool{}
	var projects []ProjectFindings

	for _, dir := range dirs {
		findings := scanDir(dir)
		ruleSet := map[string]bool{}
		bySev := map[string]int{}
		for _, f := range findings {
			ruleSet[f.ID] = true
			bySev[string(f.Severity)]++
		}

		ids := sortedKeys(ruleSet)
		projects = append(projects, ProjectFindings{
			Path:       dir,
			FindingIDs: ids,
			Count:      len(findings),
			BySeverity: bySev,
		})
		rulesByProject[dir] = ruleSet
	}

	commonRules := findCommonRules(rulesByProject)
	uniqueByProject := findUniqueRules(rulesByProject, commonRules)

	return CompareResult{
		Projects:        projects,
		CommonRules:     commonRules,
		UniqueByProject: uniqueByProject,
		TotalProjects:   len(dirs),
	}
}

func findCommonRules(rulesByProject map[string]map[string]bool) []string {
	if len(rulesByProject) == 0 {
		return nil
	}

	allRules := map[string]int{}
	for _, rules := range rulesByProject {
		for r := range rules {
			allRules[r]++
		}
	}

	n := len(rulesByProject)
	var common []string
	for r, count := range allRules {
		if count == n {
			common = append(common, r)
		}
	}
	sort.Strings(common)
	return common
}

func findUniqueRules(rulesByProject map[string]map[string]bool, common []string) map[string][]string {
	commonSet := map[string]bool{}
	for _, r := range common {
		commonSet[r] = true
	}

	unique := map[string][]string{}
	for project, ruleSet := range rulesByProject {
		var projectUnique []string
		for r := range ruleSet {
			if !commonSet[r] {
				isUnique := true
				for otherProject, otherRules := range rulesByProject {
					if otherProject != project && otherRules[r] {
						isUnique = false
						break
					}
				}
				if isUnique {
					projectUnique = append(projectUnique, r)
				}
			}
		}
		sort.Strings(projectUnique)
		if len(projectUnique) > 0 {
			unique[project] = projectUnique
		}
	}
	return unique
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func printCompareText(r CompareResult) {
	fmt.Printf("Comparing %d projects:\n\n", r.TotalProjects)

	for _, p := range r.Projects {
		fmt.Printf("  %s: %d finding(s)", p.Path, p.Count)
		if len(p.BySeverity) > 0 {
			var parts []string
			for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
				if n := p.BySeverity[sev]; n > 0 {
					parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(sev)))
				}
			}
			if len(parts) > 0 {
				fmt.Printf(" (%s)", strings.Join(parts, ", "))
			}
		}
		fmt.Println()
	}

	fmt.Println()
	if len(r.CommonRules) > 0 {
		fmt.Printf("Common rules (%d): %s\n", len(r.CommonRules), strings.Join(r.CommonRules, ", "))
	} else {
		fmt.Println("No common rules across all projects.")
	}

	if len(r.UniqueByProject) > 0 {
		fmt.Println("\nUnique rules by project:")
		for project, ruleList := range r.UniqueByProject {
			fmt.Printf("  %s: %s\n", project, strings.Join(ruleList, ", "))
		}
	}
}

