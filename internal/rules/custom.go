package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type CustomRule struct {
	ID          string   `yaml:"id" json:"id"`
	Severity    Severity `yaml:"severity" json:"severity"`
	Category    string   `yaml:"category" json:"category"`
	Pattern     string   `yaml:"pattern" json:"pattern"`
	FilePattern string   `yaml:"file_pattern" json:"file_pattern"`
	Message     string   `yaml:"message" json:"message"`
	Description string   `yaml:"description" json:"description"`

	compiled *regexp.Regexp
}

type customRulesFile struct {
	Rules []CustomRule `yaml:"rules"`
}

func LoadCustomRules(path string) ([]CustomRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f customRulesFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	for i := range f.Rules {
		r := &f.Rules[i]
		if !strings.HasPrefix(r.ID, "custom_") {
			return nil, fmt.Errorf("rule %q: id must start with 'custom_'", r.ID)
		}
		if r.Pattern == "" {
			return nil, fmt.Errorf("rule %q: pattern is required", r.ID)
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %q: invalid pattern: %w", r.ID, err)
		}
		r.compiled = re
		if r.Severity == "" {
			r.Severity = SeverityMedium
		}
		if r.Category == "" {
			r.Category = "custom"
		}
	}
	return f.Rules, nil
}

func MatchCustomRules(rules []CustomRule, filename string, content []byte) []Finding {
	var findings []Finding
	lines := strings.Split(string(content), "\n")
	for _, rule := range rules {
		if rule.FilePattern != "" {
			matched, _ := filepath.Match(rule.FilePattern, filepath.Base(filename))
			if !matched {
				continue
			}
		}
		for i, line := range lines {
			if rule.compiled != nil && rule.compiled.MatchString(line) {
				findings = append(findings, Finding{
					ID:       rule.ID,
					Severity: rule.Severity,
					Title:    rule.Message,
					File:     filename,
					Line:     i + 1,
					Evidence: strings.TrimSpace(line),
					Why:      rule.Description,
					Fix:      fmt.Sprintf("Address finding from custom rule %s", rule.ID),
				})
			}
		}
	}
	return findings
}

func FindCustomRulesFile(root string) string {
	p := filepath.Join(root, ".tasia", "rules.yaml")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}
