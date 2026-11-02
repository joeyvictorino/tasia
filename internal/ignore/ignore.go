// Package ignore parses .tasiaignore files and applies suppression
// policies to findings. An entry can suppress a rule everywhere, all
// findings in a file, or a specific rule in a specific file. Glob
// patterns are supported for file matching.
package ignore

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Entry is one parsed line from a .tasiaignore file.
type Entry struct {
	RuleID      string // empty means "any rule"
	FilePattern string // empty means "any file"; supports filepath.Match globs
}

// Policy holds the parsed ignore rules from a .tasiaignore file and any
// inline tasia:disable directives found in source files.
type Policy struct {
	Entries    []Entry
	InlineKeys map[inlineKey]bool
}

// Load reads a .tasiaignore from the given directory root. Returns a zero
// Policy (matches nothing) if the file does not exist. Returns an error only
// on I/O failures other than "not found".
func Load(root string) (*Policy, error) {
	path := filepath.Join(root, ".tasiaignore")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Policy{}, nil
		}
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads ignore entries from a reader (one per line).
//
// Format:
//
//	# comment
//	exposed_inference                           # ignore rule ID everywhere
//	docker-compose.dev.yml                      # ignore all findings in file
//	exposed_inference docker-compose.dev.yml    # ignore rule only in that file
//
// Rule IDs contain only [a-z0-9_]. Anything else is treated as a file
// pattern (supports filepath.Match globs such as examples/*).
func Parse(r *os.File) (*Policy, error) {
	var entries []Entry
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip inline comments.
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		switch len(parts) {
		case 1:
			tok := parts[0]
			if looksLikeRuleID(tok) {
				entries = append(entries, Entry{RuleID: tok})
			} else {
				entries = append(entries, Entry{FilePattern: tok})
			}
		case 2:
			first, second := parts[0], parts[1]
			if looksLikeRuleID(first) {
				entries = append(entries, Entry{RuleID: first, FilePattern: second})
			} else if looksLikeRuleID(second) {
				entries = append(entries, Entry{RuleID: second, FilePattern: first})
			} else {
				entries = append(entries, Entry{FilePattern: first})
				entries = append(entries, Entry{FilePattern: second})
			}
		default:
			for _, tok := range parts {
				if looksLikeRuleID(tok) {
					entries = append(entries, Entry{RuleID: tok})
				} else {
					entries = append(entries, Entry{FilePattern: tok})
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return &Policy{Entries: entries}, nil
}

// Suppresses returns true if the policy says this finding should be hidden
// (file-level .tasiaignore check only; use SuppressesAt for line-level).
func (p *Policy) Suppresses(ruleID, file string) bool {
	for _, e := range p.Entries {
		if e.matchesRule(ruleID) && e.matchesFile(file) {
			return true
		}
	}
	return false
}

// SuppressesAt returns true if either a .tasiaignore entry or an inline
// tasia:disable directive suppresses this finding.
func (p *Policy) SuppressesAt(ruleID, file string, line int) bool {
	if p.Suppresses(ruleID, file) {
		return true
	}
	if p.InlineKeys != nil && p.InlineKeys[inlineKey{File: file, Line: line, RuleID: ruleID}] {
		return true
	}
	return false
}

// AddInline merges inline suppressions into the policy.
func (p *Policy) AddInline(keys map[inlineKey]bool) {
	if len(keys) == 0 {
		return
	}
	if p.InlineKeys == nil {
		p.InlineKeys = make(map[inlineKey]bool)
	}
	for k := range keys {
		p.InlineKeys[k] = true
	}
}

func (e *Entry) matchesRule(id string) bool {
	if e.RuleID == "" {
		return true
	}
	return e.RuleID == id
}

func (e *Entry) matchesFile(file string) bool {
	if e.FilePattern == "" {
		return true
	}
	if e.FilePattern == file {
		return true
	}
	matched, _ := filepath.Match(e.FilePattern, file)
	if matched {
		return true
	}
	// Also try matching against just the base name.
	matched, _ = filepath.Match(e.FilePattern, filepath.Base(file))
	return matched
}

// looksLikeRuleID returns true if the token consists only of lowercase ascii,
// digits and underscores — the format used by tasia rule IDs.
func looksLikeRuleID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}
