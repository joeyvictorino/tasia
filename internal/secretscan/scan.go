package secretscan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type SecretPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
	Type     string
}

type SecretFinding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Type     string `json:"type"`
	Pattern  string `json:"pattern_name"`
	Severity string `json:"severity"`
	Masked   string `json:"masked"`
	Context  string `json:"context"`
}

type ScanResult struct {
	Path         string         `json:"path"`
	TotalFiles   int            `json:"total_files"`
	SecretsFound int            `json:"secrets_found"`
	BySeverity   map[string]int `json:"by_severity"`
	ByType       map[string]int `json:"by_type"`
	Findings     []SecretFinding `json:"findings"`
}

var Patterns = []SecretPattern{
	{Name: "aws_access_key", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Severity: "critical", Type: "api_key"},
	{Name: "aws_secret_key", Pattern: regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`), Severity: "critical", Type: "api_key"},
	{Name: "github_token", Pattern: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`), Severity: "critical", Type: "token"},
	{Name: "openai_api_key", Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`), Severity: "high", Type: "api_key"},
	{Name: "anthropic_api_key", Pattern: regexp.MustCompile(`sk-ant-[A-Za-z0-9-]{20,}`), Severity: "high", Type: "api_key"},
	{Name: "generic_api_key", Pattern: regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?[A-Za-z0-9]{20,}['"]?`), Severity: "high", Type: "api_key"},
	{Name: "password_in_url", Pattern: regexp.MustCompile(`://[^:\s]+:[^@\s]+@[^\s]+`), Severity: "critical", Type: "password"},
	{Name: "private_key", Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), Severity: "critical", Type: "certificate"},
	{Name: "database_connection_string", Pattern: regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^\s]+`), Severity: "high", Type: "connection_string"},
	{Name: "jwt_token", Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), Severity: "high", Type: "token"},
	{Name: "slack_webhook", Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`), Severity: "high", Type: "token"},
	{Name: "bearer_token", Pattern: regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}`), Severity: "high", Type: "token"},
	{Name: "docker_registry_password", Pattern: regexp.MustCompile(`(?i)(docker_password|registry_password|DOCKER_AUTH)\s*[=:]\s*\S+`), Severity: "high", Type: "password"},
	{Name: "gcp_service_account", Pattern: regexp.MustCompile(`"type"\s*:\s*"service_account"`), Severity: "high", Type: "api_key"},
	{Name: "azure_storage_key", Pattern: regexp.MustCompile(`(?i)(AccountKey|azure_storage_key)\s*[=:]\s*[A-Za-z0-9+/=]{40,}`), Severity: "high", Type: "api_key"},
	{Name: "generic_secret", Pattern: regexp.MustCompile(`(?i)(secret|password|passwd|pwd)\s*[=:]\s*['"]?[^\s'"]{8,}['"]?`), Severity: "medium", Type: "password"},
	{Name: "base64_encoded_key", Pattern: regexp.MustCompile(`(?i)(key|secret|token)\s*[=:]\s*[A-Za-z0-9+/]{40,}={0,2}`), Severity: "medium", Type: "api_key"},
}

var scanExtensions = map[string]bool{
	".env": true, ".yaml": true, ".yml": true,
	".tf": true, ".json": true, ".toml": true,
	".properties": true, ".cfg": true, ".conf": true,
	".ini": true,
}

func isScannableFile(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, "Dockerfile") || strings.HasPrefix(base, "docker-compose") {
		return true
	}
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}
	ext := filepath.Ext(path)
	return scanExtensions[ext]
}

func ScanDirectory(path string, recursive bool) (ScanResult, error) {
	result := ScanResult{
		Path:       path,
		BySeverity: map[string]int{},
		ByType:     map[string]int{},
	}

	var files []string
	if recursive {
		err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				base := filepath.Base(p)
				if base == ".git" || base == "node_modules" || base == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if isScannableFile(p) {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return result, err
		}
	} else {
		entries, err := os.ReadDir(path)
		if err != nil {
			return result, err
		}
		for _, e := range entries {
			if !e.IsDir() {
				p := filepath.Join(path, e.Name())
				if isScannableFile(p) {
					files = append(files, p)
				}
			}
		}
	}

	result.TotalFiles = len(files)

	for _, fpath := range files {
		findings, err := ScanFile(fpath, path)
		if err != nil {
			continue
		}
		result.Findings = append(result.Findings, findings...)
	}

	result.SecretsFound = len(result.Findings)
	for _, f := range result.Findings {
		result.BySeverity[f.Severity]++
		result.ByType[f.Type]++
	}

	return result, nil
}

func ScanFile(fpath, basePath string) ([]SecretFinding, error) {
	f, err := os.Open(fpath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	relPath, _ := filepath.Rel(basePath, fpath)
	if relPath == "" {
		relPath = fpath
	}

	var findings []SecretFinding
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for _, pat := range Patterns {
			if pat.Pattern.MatchString(line) {
				match := pat.Pattern.FindString(line)
				findings = append(findings, SecretFinding{
					File:     relPath,
					Line:     lineNum,
					Type:     pat.Type,
					Pattern:  pat.Name,
					Severity: pat.Severity,
					Masked:   maskValue(match),
					Context:  truncateLine(line, 120),
				})
			}
		}
	}

	return findings, nil
}

func maskValue(val string) string {
	if len(val) <= 4 {
		return "****"
	}
	return val[:4] + "****"
}

func truncateLine(line string, maxLen int) string {
	line = strings.TrimSpace(line)
	if len(line) > maxLen {
		return line[:maxLen] + "..."
	}
	return line
}

func ScanFileContent(content, filename string) []SecretFinding {
	var findings []SecretFinding
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		for _, pat := range Patterns {
			if pat.Pattern.MatchString(line) {
				match := pat.Pattern.FindString(line)
				findings = append(findings, SecretFinding{
					File:     filename,
					Line:     i + 1,
					Type:     pat.Type,
					Pattern:  pat.Name,
					Severity: pat.Severity,
					Masked:   maskValue(match),
					Context:  truncateLine(line, 120),
				})
			}
		}
	}
	return findings
}

func FormatText(r ScanResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Secret Scan (%d files scanned, %d secrets found)\n\n", r.TotalFiles, r.SecretsFound)

	if r.SecretsFound == 0 {
		fmt.Fprintln(&b, "No secrets detected.")
		return b.String()
	}

	fmt.Fprintln(&b, "By Severity:")
	sevOrder := []string{"critical", "high", "medium", "low"}
	for _, sev := range sevOrder {
		if count, ok := r.BySeverity[sev]; ok {
			fmt.Fprintf(&b, "  %-10s %d\n", sev, count)
		}
	}
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "By Type:")
	types := make([]string, 0, len(r.ByType))
	for t := range r.ByType {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		fmt.Fprintf(&b, "  %-20s %d\n", t, r.ByType[t])
	}
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "Findings:")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  [%s] %s:%d (%s) %s\n", strings.ToUpper(f.Severity), f.File, f.Line, f.Pattern, f.Masked)
	}

	return b.String()
}

func FormatJSON(r ScanResult) string {
	out, _ := json.MarshalIndent(r, "", "  ")
	return string(out)
}
