package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/joeyvictorino/tasia/internal/config"
	"github.com/joeyvictorino/tasia/internal/rules"
	"gopkg.in/yaml.v3"
)

// ValidationIssue describes a problem found in a config file.
type ValidationIssue struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Severity string `json:"severity"` // "error" or "warning"
	Message  string `json:"message"`
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	path := fs.String("path", ".", "directory containing config files")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var issues []ValidationIssue
	issues = append(issues, validateRC(absPath)...)
	issues = append(issues, validateIgnore(absPath)...)

	switch *format {
	case "json":
		data, err := json.MarshalIndent(issues, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		if len(issues) == 0 {
			fmt.Println("tasia validate: all config files are valid")
		} else {
			for _, i := range issues {
				prefix := "WARNING"
				if i.Severity == "error" {
					prefix = "ERROR"
				}
				if i.Line > 0 {
					fmt.Printf("[%s] %s:%d: %s\n", prefix, i.File, i.Line, i.Message)
				} else {
					fmt.Printf("[%s] %s: %s\n", prefix, i.File, i.Message)
				}
			}
			errors := 0
			for _, i := range issues {
				if i.Severity == "error" {
					errors++
				}
			}
			fmt.Fprintf(os.Stderr, "tasia validate: %d issue(s) (%d errors, %d warnings)\n",
				len(issues), errors, len(issues)-errors)
		}
	}

	for _, i := range issues {
		if i.Severity == "error" {
			os.Exit(1)
		}
	}
	return nil
}

var ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func validateRC(dir string) []ValidationIssue {
	var issues []ValidationIssue
	catalog := rules.CatalogMap()

	rcPath := ""
	for _, name := range []string{".tasiarc.yaml", ".tasiarc.yml"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			rcPath = p
			break
		}
	}
	if rcPath == "" {
		return nil // no config file, nothing to validate
	}

	relName := filepath.Base(rcPath)
	data, err := os.ReadFile(rcPath)
	if err != nil {
		return []ValidationIssue{{File: relName, Severity: "error", Message: fmt.Sprintf("cannot read: %v", err)}}
	}

	// Check YAML parses
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return []ValidationIssue{{File: relName, Severity: "error", Message: fmt.Sprintf("invalid YAML: %v", err)}}
	}

	// Check for unknown top-level keys
	knownKeys := map[string]bool{"severities": true, "schema_version": true}
	for k := range raw {
		if !knownKeys[k] {
			issues = append(issues, ValidationIssue{
				File:     relName,
				Severity: "warning",
				Message:  fmt.Sprintf("unknown key %q", k),
			})
		}
	}

	// Validate severities
	cfg, err := config.Load(dir)
	if err != nil {
		return append(issues, ValidationIssue{File: relName, Severity: "error", Message: fmt.Sprintf("parse error: %v", err)})
	}

	for ruleID, sev := range cfg.Severities {
		if _, exists := catalog[ruleID]; !exists {
			issues = append(issues, ValidationIssue{
				File:     relName,
				Severity: "error",
				Message:  fmt.Sprintf("unknown rule ID %q in severities", ruleID),
			})
		}
		if !config.ValidSeverity(sev) {
			issues = append(issues, ValidationIssue{
				File:     relName,
				Severity: "error",
				Message:  fmt.Sprintf("invalid severity %q for rule %q (want CRITICAL, HIGH, MEDIUM or LOW)", sev, ruleID),
			})
		}
	}

	return issues
}

func validateIgnore(dir string) []ValidationIssue {
	var issues []ValidationIssue
	ignorePath := filepath.Join(dir, ".tasiaignore")
	catalog := rules.CatalogMap()

	f, err := os.Open(ignorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return []ValidationIssue{{File: ".tasiaignore", Severity: "error", Message: fmt.Sprintf("cannot read: %v", err)}}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		for _, part := range parts {
			if ruleIDPattern.MatchString(part) {
				// Looks like a rule ID — check if it exists
				if _, exists := catalog[part]; !exists {
					issues = append(issues, ValidationIssue{
						File:     ".tasiaignore",
						Line:     lineNum,
						Severity: "warning",
						Message:  fmt.Sprintf("unknown rule ID %q (not in catalog)", part),
					})
				}
			}
			// File patterns are harder to validate — just check glob syntax
			if strings.ContainsAny(part, "*?[") {
				if _, err := filepath.Match(part, "test"); err != nil {
					issues = append(issues, ValidationIssue{
						File:     ".tasiaignore",
						Line:     lineNum,
						Severity: "error",
						Message:  fmt.Sprintf("invalid glob pattern %q: %v", part, err),
					})
				}
			}
		}
	}

	return issues
}
