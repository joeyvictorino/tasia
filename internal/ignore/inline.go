package ignore

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// inlineKey uniquely identifies a line-level suppression.
type inlineKey struct {
	File   string
	Line   int
	RuleID string
}

// ScanInline walks the directory tree and collects inline tasia:disable
// directives from comments in YAML, env, Dockerfile, HCL and nginx/Caddy
// files. A directive on a line suppresses findings on that same line and the
// line immediately below it (so the comment can sit above the flagged line).
//
// Supported forms:
//
//	# tasia:disable=rule_id
//	# tasia:disable=rule_id1,rule_id2
//	// tasia:disable=rule_id          (HCL/Terraform)
func ScanInline(root string) map[inlineKey]bool {
	suppressions := map[inlineKey]bool{}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.Name() == ".tasia" {
				return filepath.SkipDir
			}
			return nil
		}
		if !isScannableFile(info.Name()) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		scanFile(path, rel, suppressions)
		return nil
	})
	return suppressions
}

func isScannableFile(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range []string{".yml", ".yaml", ".env", ".tf", ".hcl", ".conf"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	if strings.HasPrefix(lower, ".env") {
		return true
	}
	if lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") {
		return true
	}
	if lower == "caddyfile" {
		return true
	}
	return false
}

func scanFile(path, rel string, out map[inlineKey]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		rules := extractDisableRules(line)
		for _, ruleID := range rules {
			out[inlineKey{File: rel, Line: lineNum, RuleID: ruleID}] = true
			out[inlineKey{File: rel, Line: lineNum + 1, RuleID: ruleID}] = true
		}
	}
}

// extractDisableRules parses tasia:disable=rule1,rule2 from a comment.
func extractDisableRules(line string) []string {
	const marker = "tasia:disable="
	idx := strings.Index(line, marker)
	if idx < 0 {
		return nil
	}
	// Verify the marker appears after a comment character (# or //).
	before := line[:idx]
	hasHash := strings.Contains(before, "#")
	hasSlash := strings.Contains(before, "//")
	if !hasHash && !hasSlash {
		return nil
	}
	rest := line[idx+len(marker):]
	// Take until whitespace or end of line.
	if sp := strings.IndexAny(rest, " \t#"); sp >= 0 {
		rest = rest[:sp]
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return nil
	}
	parts := strings.Split(rest, ",")
	var rules []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if looksLikeRuleID(p) {
			rules = append(rules, p)
		}
	}
	return rules
}
