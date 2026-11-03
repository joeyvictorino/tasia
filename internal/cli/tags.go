package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type tagEntry struct {
	Rule string   `json:"rule"`
	Tags []string `json:"tags"`
	Note string   `json:"note,omitempty"`
}

type tagStore struct {
	Entries []tagEntry `json:"entries"`
}

func runTags(args []string) error {
	if len(args) == 0 {
		return runTagsList(nil)
	}
	switch args[0] {
	case "list":
		return runTagsList(args[1:])
	case "add":
		return runTagsAdd(args[1:])
	case "remove":
		return runTagsRemove(args[1:])
	default:
		return fmt.Errorf("unknown tags subcommand: %s (use list, add, or remove)", args[0])
	}
}

func runTagsList(args []string) error {
	fs := flag.NewFlagSet("tags list", flag.ContinueOnError)
	path := fs.String("path", ".", "project directory")
	format := fs.String("format", "text", "output format: text or json")
	filterTag := fs.String("tag", "", "filter by tag")
	if args != nil {
		if err := fs.Parse(args); err != nil {
			return err
		}
	}

	store, storePath, err := loadTagStore(*path)
	if err != nil {
		return err
	}

	entries := store.Entries
	if *filterTag != "" {
		var filtered []tagEntry
		for _, e := range entries {
			for _, t := range e.Tags {
				if t == *filterTag {
					filtered = append(filtered, e)
					break
				}
			}
		}
		entries = filtered
	}

	if *format == "json" {
		out := map[string]any{
			"path":    storePath,
			"entries": entries,
			"count":   len(entries),
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("Finding tags (%s):\n", storePath)
		if len(entries) == 0 {
			fmt.Println("  (none)")
		} else {
			for _, e := range entries {
				tags := strings.Join(e.Tags, ", ")
				line := fmt.Sprintf("  %-40s [%s]", e.Rule, tags)
				if e.Note != "" {
					line += fmt.Sprintf("  # %s", e.Note)
				}
				fmt.Println(line)
			}
		}
		fmt.Printf("\nTotal: %d tagged rules\n", len(entries))
	}
	return nil
}

func runTagsAdd(args []string) error {
	fs := flag.NewFlagSet("tags add", flag.ContinueOnError)
	path := fs.String("path", ".", "project directory")
	rule := fs.String("rule", "", "rule ID to tag (required)")
	tag := fs.String("tag", "", "tag to add (required)")
	note := fs.String("note", "", "optional annotation note")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rule == "" || *tag == "" {
		return fmt.Errorf("--rule and --tag are required")
	}

	store, storePath, err := loadTagStore(*path)
	if err != nil {
		return err
	}

	found := false
	for i, e := range store.Entries {
		if e.Rule == *rule {
			found = true
			for _, t := range e.Tags {
				if t == *tag {
					fmt.Printf("Tag %q already exists on rule %q\n", *tag, *rule)
					return nil
				}
			}
			store.Entries[i].Tags = append(store.Entries[i].Tags, *tag)
			sort.Strings(store.Entries[i].Tags)
			if *note != "" {
				store.Entries[i].Note = *note
			}
			break
		}
	}

	if !found {
		entry := tagEntry{Rule: *rule, Tags: []string{*tag}}
		if *note != "" {
			entry.Note = *note
		}
		store.Entries = append(store.Entries, entry)
	}

	if err := saveTagStore(storePath, store); err != nil {
		return err
	}
	fmt.Printf("Added tag %q to rule %q in %s\n", *tag, *rule, storePath)
	return nil
}

func runTagsRemove(args []string) error {
	fs := flag.NewFlagSet("tags remove", flag.ContinueOnError)
	path := fs.String("path", ".", "project directory")
	rule := fs.String("rule", "", "rule ID (required)")
	tag := fs.String("tag", "", "tag to remove (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rule == "" || *tag == "" {
		return fmt.Errorf("--rule and --tag are required")
	}

	store, storePath, err := loadTagStore(*path)
	if err != nil {
		return err
	}

	found := false
	for i, e := range store.Entries {
		if e.Rule == *rule {
			var kept []string
			for _, t := range e.Tags {
				if t == *tag {
					found = true
					continue
				}
				kept = append(kept, t)
			}
			if !found {
				return fmt.Errorf("tag %q not found on rule %q", *tag, *rule)
			}
			if len(kept) == 0 {
				store.Entries = append(store.Entries[:i], store.Entries[i+1:]...)
			} else {
				store.Entries[i].Tags = kept
			}
			break
		}
	}

	if !found {
		return fmt.Errorf("rule %q not found in tags store", *rule)
	}

	if err := saveTagStore(storePath, store); err != nil {
		return err
	}
	fmt.Printf("Removed tag %q from rule %q in %s\n", *tag, *rule, storePath)
	return nil
}

func loadTagStore(basePath string) (*tagStore, string, error) {
	absPath, err := filepath.Abs(basePath)
	if err != nil {
		return nil, "", err
	}

	storePath := filepath.Join(absPath, ".tasia", "tags.json")

	data, err := os.ReadFile(storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &tagStore{}, storePath, nil
		}
		return nil, storePath, err
	}

	var store tagStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, storePath, fmt.Errorf("parsing %s: %w", storePath, err)
	}
	return &store, storePath, nil
}

func saveTagStore(path string, store *tagStore) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}
