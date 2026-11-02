package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

var secretPatterns = regexp.MustCompile(`(?i)(secret|password|token|key|api_key|apikey|auth|credential|private)`)

func runEnvAudit(args []string) error {
	fs := flag.NewFlagSet("env-audit", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	secretsOnly := fs.Bool("secrets-only", false, "show only secret-looking variables")
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

	result := buildEnvAudit(collected)

	if *secretsOnly {
		var filtered []envVarEntry
		for _, e := range result.Variables {
			if e.LooksSecret {
				filtered = append(filtered, e)
			}
		}
		result.Variables = filtered
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	default:
		fmt.Print(formatEnvAuditText(result))
		return nil
	}
}

type envVarEntry struct {
	Name        string   `json:"name"`
	Sources     []string `json:"sources"`
	LooksSecret bool     `json:"looks_secret"`
	MultiSource bool     `json:"multi_source"`
}

type envAuditResult struct {
	Variables    []envVarEntry `json:"variables"`
	TotalVars    int           `json:"total_vars"`
	SecretCount  int           `json:"secret_count"`
	MultiCount   int           `json:"multi_source_count"`
}

func buildEnvAudit(c *collect.Collected) envAuditResult {
	varSources := map[string]map[string]bool{}

	for _, ef := range c.EnvFiles {
		extractEnvFileVars(ef.Path, varSources)
	}

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			for _, env := range svc.Environment {
				name := envName(env)
				if name == "" {
					continue
				}
				src := fmt.Sprintf("compose:%s(%s)", filepath.Base(cf.Path), svc.Name)
				if varSources[name] == nil {
					varSources[name] = map[string]bool{}
				}
				varSources[name][src] = true
			}
		}
	}

	var entries []envVarEntry
	secretCount := 0
	multiCount := 0

	for name, srcs := range varSources {
		sources := envAuditSortedKeys(srcs)
		isSecret := secretPatterns.MatchString(name)
		isMulti := len(sources) > 1
		if isSecret {
			secretCount++
		}
		if isMulti {
			multiCount++
		}
		entries = append(entries, envVarEntry{
			Name:        name,
			Sources:     sources,
			LooksSecret: isSecret,
			MultiSource: isMulti,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].LooksSecret != entries[j].LooksSecret {
			return entries[i].LooksSecret
		}
		return entries[i].Name < entries[j].Name
	})

	return envAuditResult{
		Variables:   entries,
		TotalVars:   len(entries),
		SecretCount: secretCount,
		MultiCount:  multiCount,
	}
}

func extractEnvFileVars(path string, varSources map[string]map[string]bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	src := fmt.Sprintf("env:%s", filepath.Base(path))
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := envName(line)
		if name == "" {
			continue
		}
		if varSources[name] == nil {
			varSources[name] = map[string]bool{}
		}
		varSources[name][src] = true
	}
}

func envName(s string) string {
	eq := strings.IndexByte(s, '=')
	if eq < 0 {
		return strings.TrimSpace(s)
	}
	if eq == 0 {
		return ""
	}
	return strings.TrimSpace(s[:eq])
}

func envAuditSortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func formatEnvAuditText(r envAuditResult) string {
	var b strings.Builder
	b.WriteString("Environment Variable Audit\n")
	b.WriteString("========================================\n")
	fmt.Fprintf(&b, "Total variables: %d\n", r.TotalVars)
	fmt.Fprintf(&b, "Secret-looking: %d\n", r.SecretCount)
	fmt.Fprintf(&b, "Multi-source:   %d\n\n", r.MultiCount)

	for _, v := range r.Variables {
		flag := " "
		if v.LooksSecret {
			flag = "!"
		}
		fmt.Fprintf(&b, "  %s %-30s  [%s]\n", flag, v.Name, strings.Join(v.Sources, ", "))
	}
	return b.String()
}
