package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type IgnoreEntry struct {
	Pattern string `json:"pattern"`
	Source  string `json:"source"`
}

type IgnoreReport struct {
	Path    string        `json:"path"`
	Entries []IgnoreEntry `json:"entries"`
	Count   int           `json:"count"`
}

func runIgnoreCmd(args []string) error {
	if len(args) == 0 {
		return runIgnoreList(nil)
	}
	switch args[0] {
	case "list":
		return runIgnoreList(args[1:])
	case "add":
		return runIgnoreAdd(args[1:])
	case "remove":
		return runIgnoreRemove(args[1:])
	default:
		return fmt.Errorf("unknown ignore subcommand: %s (use list, add, or remove)", args[0])
	}
}

func runIgnoreList(args []string) error {
	fs := flag.NewFlagSet("ignore list", flag.ContinueOnError)
	path := fs.String("path", ".", "project directory")
	format := fs.String("format", "text", "output format: text or json")
	if args != nil {
		if err := fs.Parse(args); err != nil {
			return err
		}
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	ignorePath := filepath.Join(absPath, ".tasiaignore")
	entries, err := readIgnoreFile(ignorePath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	report := IgnoreReport{
		Path:    ignorePath,
		Entries: entries,
		Count:   len(entries),
	}

	if *format == "json" {
		out, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("Ignore patterns (%s):\n", ignorePath)
		if len(entries) == 0 {
			fmt.Println("  (none)")
		} else {
			for _, e := range entries {
				fmt.Printf("  %s\n", e.Pattern)
			}
		}
		fmt.Printf("\nTotal: %d patterns\n", len(entries))
	}
	return nil
}

func runIgnoreAdd(args []string) error {
	fs := flag.NewFlagSet("ignore add", flag.ContinueOnError)
	path := fs.String("path", ".", "project directory")
	pattern := fs.String("pattern", "", "pattern to add (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pattern == "" {
		return fmt.Errorf("--pattern is required")
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	ignorePath := filepath.Join(absPath, ".tasiaignore")
	entries, _ := readIgnoreFile(ignorePath)

	for _, e := range entries {
		if e.Pattern == *pattern {
			fmt.Printf("Pattern %q already exists in %s\n", *pattern, ignorePath)
			return nil
		}
	}

	f, err := os.OpenFile(ignorePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "%s\n", *pattern)
	if err != nil {
		return err
	}

	fmt.Printf("Added %q to %s\n", *pattern, ignorePath)
	return nil
}

func runIgnoreRemove(args []string) error {
	fs := flag.NewFlagSet("ignore remove", flag.ContinueOnError)
	path := fs.String("path", ".", "project directory")
	pattern := fs.String("pattern", "", "pattern to remove (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pattern == "" {
		return fmt.Errorf("--pattern is required")
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	ignorePath := filepath.Join(absPath, ".tasiaignore")
	entries, err := readIgnoreFile(ignorePath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", ignorePath, err)
	}

	var kept []string
	found := false
	for _, e := range entries {
		if e.Pattern == *pattern {
			found = true
			continue
		}
		kept = append(kept, e.Pattern)
	}

	if !found {
		return fmt.Errorf("pattern %q not found in %s", *pattern, ignorePath)
	}

	content := strings.Join(kept, "\n")
	if len(kept) > 0 {
		content += "\n"
	}
	if err := os.WriteFile(ignorePath, []byte(content), 0644); err != nil {
		return err
	}

	fmt.Printf("Removed %q from %s\n", *pattern, ignorePath)
	return nil
}

func readIgnoreFile(path string) ([]IgnoreEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []IgnoreEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, IgnoreEntry{Pattern: line, Source: ".tasiaignore"})
	}
	return entries, nil
}
