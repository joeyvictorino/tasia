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

const currentSchemaVersion = "2"

type migrateConfig struct {
	SchemaVersion string            `yaml:"schema_version,omitempty"`
	Severities    map[string]string `yaml:"severities"`
}

func runMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	path := fs.String("path", ".tasiarc.yaml", "path to .tasiarc.yaml file")
	dryRun := fs.Bool("dry-run", false, "show what would change without writing")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", absPath, err)
	}

	migrated, changes, err := migrateConfig_(data)
	if err != nil {
		return fmt.Errorf("migrating %s: %w", absPath, err)
	}

	if len(changes) == 0 {
		fmt.Fprintln(os.Stderr, "tasia migrate: config is already up to date")
		return nil
	}

	if *dryRun {
		fmt.Fprintln(os.Stderr, "tasia migrate: would apply these changes:")
		for _, c := range changes {
			fmt.Fprintf(os.Stderr, "  - %s\n", c)
		}
		return nil
	}

	if err := os.WriteFile(absPath, []byte(migrated), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "tasia migrate: updated %s (%d changes)\n", absPath, len(changes))
	for _, c := range changes {
		fmt.Fprintf(os.Stderr, "  - %s\n", c)
	}
	return nil
}

func migrateConfig_(data []byte) (string, []string, error) {
	var mc migrateConfig
	if err := yaml.Unmarshal(data, &mc); err != nil {
		return "", nil, err
	}
	if mc.Severities == nil {
		mc.Severities = map[string]string{}
	}

	var changes []string

	catalog := rules.Catalog()
	catalogIDs := map[string]rules.RuleInfo{}
	for _, r := range catalog {
		catalogIDs[r.ID] = r
	}

	existingIDs := map[string]bool{}
	for k := range mc.Severities {
		existingIDs[k] = true
	}

	// Check raw content for commented-out rule references
	content := string(data)
	for _, r := range catalog {
		if strings.Contains(content, r.ID) {
			existingIDs[r.ID] = true
		}
	}

	var added []string
	for _, r := range catalog {
		if !existingIDs[r.ID] {
			added = append(added, r.ID)
		}
	}

	if len(added) > 0 {
		sort.Strings(added)
		changes = append(changes, fmt.Sprintf("add %d new rule(s): %s", len(added), strings.Join(added, ", ")))
	}

	if mc.SchemaVersion != currentSchemaVersion {
		oldVer := mc.SchemaVersion
		if oldVer == "" {
			oldVer = "1"
		}
		changes = append(changes, fmt.Sprintf("bump schema_version from %s to %s", oldVer, currentSchemaVersion))
	}

	if len(changes) == 0 {
		return string(data), nil, nil
	}

	// Rebuild config with all rules
	var b strings.Builder
	b.WriteString(fmt.Sprintf("schema_version: \"%s\"\n\n", currentSchemaVersion))
	b.WriteString("# tasia configuration — severity overrides\n")
	b.WriteString("# Valid values: critical, high, medium, low\n\n")
	b.WriteString("severities:\n")

	currentCategory := ""
	for _, r := range catalog {
		if r.Category != currentCategory {
			currentCategory = r.Category
			b.WriteString(fmt.Sprintf("\n  # --- %s ---\n", currentCategory))
		}
		if override, ok := mc.Severities[r.ID]; ok {
			b.WriteString(fmt.Sprintf("  %s: %s\n", r.ID, strings.ToLower(strings.TrimSpace(override))))
		} else {
			b.WriteString(fmt.Sprintf("  # %s: %s\n", r.ID, strings.ToLower(string(r.Default))))
		}
	}

	// Preserve unknown keys
	var unknownKeys []string
	for k := range mc.Severities {
		if _, ok := catalogIDs[k]; !ok {
			unknownKeys = append(unknownKeys, k)
		}
	}
	if len(unknownKeys) > 0 {
		sort.Strings(unknownKeys)
		b.WriteString("\n  # --- unknown (not in current catalog) ---\n")
		for _, k := range unknownKeys {
			b.WriteString(fmt.Sprintf("  %s: %s\n", k, mc.Severities[k]))
		}
	}

	return b.String(), changes, nil
}
