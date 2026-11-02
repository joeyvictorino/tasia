package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/joeyvictorino/tasia/internal/config"
)

type LintIssue struct {
	File    string `json:"file"`
	Message string `json:"message"`
	Level   string `json:"level"`
}

type LintReport struct {
	Issues []LintIssue `json:"issues"`
	Clean  bool        `json:"clean"`
}

func lintConfigFile(path string) []LintIssue {
	var issues []LintIssue

	data, err := os.ReadFile(path)
	if err != nil {
		issues = append(issues, LintIssue{File: path, Message: fmt.Sprintf("cannot read: %v", err), Level: "error"})
		return issues
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		issues = append(issues, LintIssue{File: path, Message: fmt.Sprintf("invalid YAML: %v", err), Level: "error"})
		return issues
	}

	knownKeys := map[string]bool{
		"severities": true,
	}
	for key := range raw {
		if !knownKeys[key] {
			issues = append(issues, LintIssue{
				File:    path,
				Message: fmt.Sprintf("unknown key %q", key),
				Level:   "warning",
			})
		}
	}

	if sevs, ok := raw["severities"]; ok {
		if sevMap, ok := sevs.(map[string]any); ok {
			for ruleID, val := range sevMap {
				sev, ok := val.(string)
				if !ok {
					issues = append(issues, LintIssue{
						File:    path,
						Message: fmt.Sprintf("severity for %q must be a string", ruleID),
						Level:   "error",
					})
					continue
				}
				if !config.ValidSeverity(strings.ToUpper(strings.TrimSpace(sev))) {
					issues = append(issues, LintIssue{
						File:    path,
						Message: fmt.Sprintf("invalid severity %q for rule %q (must be CRITICAL, HIGH, MEDIUM, or LOW)", sev, ruleID),
						Level:   "error",
					})
				}
			}
		}
	}

	return issues
}

func lintCustomRulesFile(path string) []LintIssue {
	var issues []LintIssue

	data, err := os.ReadFile(path)
	if err != nil {
		issues = append(issues, LintIssue{File: path, Message: fmt.Sprintf("cannot read: %v", err), Level: "error"})
		return issues
	}

	var raw struct {
		Rules []map[string]any `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		issues = append(issues, LintIssue{File: path, Message: fmt.Sprintf("invalid YAML: %v", err), Level: "error"})
		return issues
	}

	seenIDs := map[string]bool{}
	for i, rule := range raw.Rules {
		id, _ := rule["id"].(string)
		if id == "" {
			issues = append(issues, LintIssue{
				File:    path,
				Message: fmt.Sprintf("rule[%d]: missing required field 'id'", i),
				Level:   "error",
			})
		} else {
			if !strings.HasPrefix(id, "custom_") {
				issues = append(issues, LintIssue{
					File:    path,
					Message: fmt.Sprintf("rule %q: id must start with 'custom_'", id),
					Level:   "error",
				})
			}
			if seenIDs[id] {
				issues = append(issues, LintIssue{
					File:    path,
					Message: fmt.Sprintf("rule %q: duplicate rule ID", id),
					Level:   "error",
				})
			}
			seenIDs[id] = true
		}

		pattern, _ := rule["pattern"].(string)
		if pattern == "" {
			issues = append(issues, LintIssue{
				File:    path,
				Message: fmt.Sprintf("rule %q: missing required field 'pattern'", id),
				Level:   "error",
			})
		} else {
			if _, err := regexp.Compile(pattern); err != nil {
				issues = append(issues, LintIssue{
					File:    path,
					Message: fmt.Sprintf("rule %q: invalid regex pattern: %v", id, err),
					Level:   "error",
				})
			}
		}

		if sev, ok := rule["severity"].(string); ok && sev != "" {
			if !config.ValidSeverity(strings.ToUpper(strings.TrimSpace(sev))) {
				issues = append(issues, LintIssue{
					File:    path,
					Message: fmt.Sprintf("rule %q: invalid severity %q", id, sev),
					Level:   "error",
				})
			}
		}
	}

	return issues
}

func runLint(args []string) error {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	path := fs.String("path", ".", "directory to check")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var allIssues []LintIssue

	for _, name := range []string{".tasiarc.yaml", ".tasiarc.yml"} {
		cfgPath := filepath.Join(absPath, name)
		if _, err := os.Stat(cfgPath); err == nil {
			allIssues = append(allIssues, lintConfigFile(cfgPath)...)
		}
	}

	rulesPath := filepath.Join(absPath, ".tasia", "rules.yaml")
	if _, err := os.Stat(rulesPath); err == nil {
		allIssues = append(allIssues, lintCustomRulesFile(rulesPath)...)
	}

	report := LintReport{
		Issues: allIssues,
		Clean:  len(allIssues) == 0,
	}

	switch *format {
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		if report.Clean {
			fmt.Println("No issues found.")
		} else {
			fmt.Printf("Found %d issue(s):\n\n", len(report.Issues))
			for _, issue := range report.Issues {
				fmt.Printf("  [%s] %s: %s\n", strings.ToUpper(issue.Level), issue.File, issue.Message)
			}
		}
	}

	if !report.Clean {
		return fmt.Errorf("lint found %d issue(s)", len(report.Issues))
	}
	return nil
}
