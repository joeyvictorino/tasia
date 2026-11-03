package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	
	"path/filepath"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/config"
	"github.com/joeyvictorino/tasia/internal/ignore"
	"github.com/joeyvictorino/tasia/internal/rules"
)

type suggestion struct {
	RuleID     string   `json:"rule_id"`
	Severity   string   `json:"severity"`
	Title      string   `json:"title"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Actions    []string `json:"actions"`
	Effort     string   `json:"effort"`
	Impact     string   `json:"impact"`
	References []string `json:"references,omitempty"`
}

type suggestResult struct {
	Total       int          `json:"total"`
	Suggestions []suggestion `json:"suggestions"`
	QuickWins   int          `json:"quick_wins"`
}

func runSuggest(args []string) error {
	fs := flag.NewFlagSet("suggest", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	severity := fs.String("severity", "", "filter by minimum severity: critical, high, medium, low")
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
	if len(collected.ParseErrors) > 0 {
		return fmt.Errorf("parse errors in %s", absPath)
	}

	findings := rules.Evaluate(collected)

	if pol, err := ignore.Load(absPath); err == nil {
		pol.AddInline(ignore.ScanInline(absPath))
		findings = filterFindings(findings, pol)
	}
	if cfg, err := config.Load(absPath); err == nil {
		findings = applySeverityOverrides(findings, cfg)
	}

	if *severity != "" {
		threshold := rules.Severity(strings.ToUpper(*severity))
		var filtered []rules.Finding
		for _, f := range findings {
			if f.Severity.Rank() >= threshold.Rank() {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	var suggestions []suggestion
	quickWins := 0
	for _, f := range findings {
		s := buildSuggestion(f)
		suggestions = append(suggestions, s)
		if s.Effort == "low" {
			quickWins++
		}
	}

	result := suggestResult{
		Total:       len(suggestions),
		Suggestions: suggestions,
		QuickWins:   quickWins,
	}

	switch *format {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		printSuggestions(result)
	}
	return nil
}

func buildSuggestion(f rules.Finding) suggestion {
	s := suggestion{
		RuleID:   f.ID,
		Severity: string(f.Severity),
		Title:    f.Title,
		File:     f.File,
		Line:     f.Line,
	}

	if f.Fix != "" {
		s.Actions = append(s.Actions, f.Fix)
	}

	cat := categoryFromID(f.ID)
	switch cat {
	case "compose":
		s.Actions = append(s.Actions, "Review docker-compose.yml service definitions")
		s.References = append(s.References, "https://docs.docker.com/compose/compose-file/")
	case "agent":
		s.Actions = append(s.Actions, "Restrict agent runtime permissions to minimum required")
	case "kubernetes":
		s.Actions = append(s.Actions, "Apply Pod Security Standards to workloads")
		s.References = append(s.References, "https://kubernetes.io/docs/concepts/security/pod-security-standards/")
	case "terraform":
		s.Actions = append(s.Actions, "Review cloud IAM policies and security groups")
	case "dockerfile":
		s.Actions = append(s.Actions, "Follow Dockerfile best practices")
		s.References = append(s.References, "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/")
	case "proxy":
		s.Actions = append(s.Actions, "Enable authentication on reverse proxy endpoints")
	}

	if len(s.Actions) == 0 {
		s.Actions = []string{"Review and remediate the finding"}
	}

	switch f.Severity {
	case rules.SeverityCritical:
		s.Effort = "high"
		s.Impact = "critical"
	case rules.SeverityHigh:
		s.Effort = "medium"
		s.Impact = "high"
	case rules.SeverityMedium:
		s.Effort = "low"
		s.Impact = "medium"
	default:
		s.Effort = "low"
		s.Impact = "low"
	}

	if strings.Contains(f.ID, "latest_tag") || strings.Contains(f.ID, "no_healthcheck") {
		s.Effort = "low"
	}

	return s
}

func printSuggestions(r suggestResult) {
	fmt.Printf("Remediation Suggestions (%d findings, %d quick wins)\n\n", r.Total, r.QuickWins)

	for i, s := range r.Suggestions {
		fmt.Printf("%d. [%s] %s\n", i+1, s.Severity, s.Title)
		fmt.Printf("   File: %s:%d\n", s.File, s.Line)
		fmt.Printf("   Effort: %s  Impact: %s\n", s.Effort, s.Impact)
		for _, a := range s.Actions {
			fmt.Printf("   -> %s\n", a)
		}
		if len(s.References) > 0 {
			for _, ref := range s.References {
				fmt.Printf("   Ref: %s\n", ref)
			}
		}
		fmt.Println()
	}
}
