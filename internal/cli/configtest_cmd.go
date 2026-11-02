package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/joeyvictorino/tasia/internal/config"
)

var knownRuleIDs = map[string]bool{
	"exposed_datastore":         true,
	"privileged_container":      true,
	"latest_image":              true,
	"docker_socket_mount":       true,
	"broad_bind_mount":          true,
	"agent_auto_approve":        true,
	"agent_auto_restart":        true,
	"vector_db_no_auth":         true,
	"agent_test_mount":          true,
	"env_token_key":             true,
	"env_hardcoded_secret":      true,
	"permissive_cors":           true,
	"dockerfile_user_root":      true,
	"dockerfile_expose_sensitive": true,
	"dockerfile_expose":         true,
	"reverse_proxy_no_auth":     true,
	"no_ai_stack_manifest":      true,
	"no_network_policy":         true,
	"no_internal_network":       true,
	"agent_shared_secret":       true,
	"restart_always_agent":      true,
	"no_auth_chroma":            true,
	"no_auth_weaviate":          true,
	"network_mode_host":         true,
	"helm_no_resource_limits":   true,
	"helm_no_security_context":  true,
	"helm_privileged":           true,
	"tf_open_ingress":           true,
	"tf_s3_public":              true,
	"tf_iam_wildcard":           true,
	"tf_gcp_open_firewall":      true,
	"tf_gcp_public_storage":     true,
	"tf_azure_open_nsg":         true,
	"tf_azure_public_storage":   true,
	"tf_lambda_no_vpc":          true,
	"tf_ecs_privileged":         true,
}

type configTestResult struct {
	ConfigPath string              `json:"config_path"`
	Valid      bool                `json:"valid"`
	Errors     []configTestError   `json:"errors,omitempty"`
	Warnings   []configTestWarning `json:"warnings,omitempty"`
	RulesOverridden int            `json:"rules_overridden"`
}

type configTestError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type configTestWarning struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func runConfigTest(args []string) error {
	fs := flag.NewFlagSet("config-test", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path (default: .tasiarc.yaml in current dir)")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := *cfgPath
	if path == "" {
		path = "."
	}

	result := validateConfig(path)

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	default:
		fmt.Print(formatConfigTestText(result))
		return nil
	}
}

func validateConfig(path string) configTestResult {
	cfg, err := config.Load(path)
	if err != nil {
		return configTestResult{
			ConfigPath: path,
			Valid:      false,
			Errors:     []configTestError{{Field: "file", Message: fmt.Sprintf("failed to load: %v", err)}},
		}
	}

	var errors []configTestError
	var warnings []configTestWarning

	for ruleID, sev := range cfg.Severities {
		if !knownRuleIDs[ruleID] {
			errors = append(errors, configTestError{
				Field:   fmt.Sprintf("severities.%s", ruleID),
				Message: fmt.Sprintf("unknown rule ID %q", ruleID),
			})
		}
		if !config.ValidSeverity(sev) {
			errors = append(errors, configTestError{
				Field:   fmt.Sprintf("severities.%s", ruleID),
				Message: fmt.Sprintf("invalid severity %q (must be CRITICAL, HIGH, MEDIUM, or LOW)", sev),
			})
		}
	}

	sevCounts := map[string]int{}
	for _, sev := range cfg.Severities {
		sevCounts[sev]++
	}
	if sevCounts["LOW"] > 10 {
		warnings = append(warnings, configTestWarning{
			Field:   "severities",
			Message: fmt.Sprintf("%d rules downgraded to LOW — consider if critical findings are being masked", sevCounts["LOW"]),
		})
	}

	return configTestResult{
		ConfigPath:      path,
		Valid:           len(errors) == 0,
		Errors:          errors,
		Warnings:        warnings,
		RulesOverridden: len(cfg.Severities),
	}
}

func formatConfigTestText(r configTestResult) string {
	var b strings.Builder
	b.WriteString("Configuration Test\n")
	b.WriteString("========================================\n")
	fmt.Fprintf(&b, "Config: %s\n", r.ConfigPath)
	fmt.Fprintf(&b, "Rules overridden: %d\n", r.RulesOverridden)

	if r.Valid {
		b.WriteString("Result: PASS\n")
	} else {
		b.WriteString("Result: FAIL\n")
	}

	if len(r.Errors) > 0 {
		b.WriteString("\nErrors:\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "  [%s] %s\n", e.Field, e.Message)
		}
	}
	if len(r.Warnings) > 0 {
		b.WriteString("\nWarnings:\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  [%s] %s\n", w.Field, w.Message)
		}
	}
	return b.String()
}
