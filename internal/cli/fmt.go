package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/rules"
	"gopkg.in/yaml.v3"
)

func runFmt(args []string) error {
	fs := flag.NewFlagSet("fmt", flag.ContinueOnError)
	path := fs.String("path", ".tasiarc.yaml", "path to .tasiarc.yaml file")
	check := fs.Bool("check", false, "exit 1 if file would change (CI mode)")
	diff := fs.Bool("diff", false, "show what would change")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	original, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", absPath, err)
	}

	formatted, err := formatConfig(original)
	if err != nil {
		return fmt.Errorf("formatting %s: %w", absPath, err)
	}

	if string(original) == formatted {
		if *check {
			fmt.Fprintln(os.Stderr, "tasia fmt: already formatted")
		}
		return nil
	}

	if *check {
		fmt.Fprintf(os.Stderr, "tasia fmt: %s would change\n", absPath)
		os.Exit(1)
	}

	if *diff {
		printDiff(string(original), formatted)
		return nil
	}

	if err := os.WriteFile(absPath, []byte(formatted), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "tasia fmt: formatted %s\n", absPath)
	return nil
}

type rawConfig struct {
	Severities map[string]string `yaml:"severities"`
}

func formatConfig(data []byte) (string, error) {
	var rc rawConfig
	if err := yaml.Unmarshal(data, &rc); err != nil {
		return "", err
	}
	if rc.Severities == nil {
		rc.Severities = map[string]string{}
	}

	for k, v := range rc.Severities {
		rc.Severities[k] = strings.ToLower(strings.TrimSpace(v))
	}

	catalog := rules.Catalog()
	catalogByID := map[string]rules.RuleInfo{}
	for _, r := range catalog {
		catalogByID[r.ID] = r
	}

	var b strings.Builder
	b.WriteString("# tasia configuration — severity overrides\n")
	b.WriteString("# Valid values: critical, high, medium, low\n")
	b.WriteString("#\n")
	b.WriteString("# See: tasia rules --format text\n\n")
	b.WriteString("severities:\n")

	currentCategory := ""
	for _, r := range catalog {
		if r.Category != currentCategory {
			currentCategory = r.Category
			b.WriteString(fmt.Sprintf("\n  # --- %s ---\n", currentCategory))
		}
		if override, ok := rc.Severities[r.ID]; ok {
			b.WriteString(fmt.Sprintf("  %s: %s\n", r.ID, override))
		} else {
			b.WriteString(fmt.Sprintf("  # %s: %s\n", r.ID, strings.ToLower(string(r.Default))))
		}
	}

	unknownKeys := unknownSeverityKeys(rc.Severities, catalogByID)
	if len(unknownKeys) > 0 {
		b.WriteString("\n  # --- unknown (not in current catalog) ---\n")
		sort.Strings(unknownKeys)
		for _, k := range unknownKeys {
			b.WriteString(fmt.Sprintf("  %s: %s\n", k, rc.Severities[k]))
		}
	}

	return b.String(), nil
}

func unknownSeverityKeys(severities map[string]string, catalog map[string]rules.RuleInfo) []string {
	var unknown []string
	for k := range severities {
		if _, ok := catalog[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	return unknown
}

func printDiff(original, formatted string) {
	origLines := strings.Split(original, "\n")
	fmtLines := strings.Split(formatted, "\n")

	maxLines := len(origLines)
	if len(fmtLines) > maxLines {
		maxLines = len(fmtLines)
	}

	for i := 0; i < maxLines; i++ {
		var origLine, fmtLine string
		if i < len(origLines) {
			origLine = origLines[i]
		}
		if i < len(fmtLines) {
			fmtLine = fmtLines[i]
		}
		if origLine != fmtLine {
			if origLine != "" {
				fmt.Printf("- %s\n", origLine)
			}
			if fmtLine != "" {
				fmt.Printf("+ %s\n", fmtLine)
			}
		}
	}
}
