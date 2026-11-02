// Package config parses .tasiarc.yaml files for user-specified
// severity overrides. The [Config.SeverityFor] method returns the
// overridden severity for a rule ID, or empty if no override is set.
package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds user overrides loaded from .tasiarc.yaml at the scan root.
type Config struct {
	Severities map[string]string `yaml:"severities"`
}

// Load reads .tasiarc.yaml from the given directory. Returns a zero Config
// if the file does not exist.
func Load(root string) (*Config, error) {
	for _, name := range []string{".tasiarc.yaml", ".tasiarc.yml"} {
		path := filepath.Join(root, name)
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		return parse(data)
	}
	return &Config{}, nil
}

func parse(data []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Severities == nil {
		c.Severities = map[string]string{}
	}
	// Normalize severity values to uppercase.
	for k, v := range c.Severities {
		c.Severities[k] = strings.ToUpper(strings.TrimSpace(v))
	}
	return &c, nil
}

// SeverityFor returns the configured severity for a rule ID, or empty if none.
func (c *Config) SeverityFor(ruleID string) string {
	if c == nil || c.Severities == nil {
		return ""
	}
	return c.Severities[ruleID]
}

// ValidSeverity returns true if s is a known severity value.
func ValidSeverity(s string) bool {
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return true
	}
	return false
}
