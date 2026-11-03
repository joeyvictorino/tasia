package envinjection

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type ServiceResult struct {
	Service  string    `json:"service"`
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices   int `json:"total_services"`
	TotalFindings   int `json:"total_findings"`
	ShellMetachar   int `json:"shell_metachar"`
	Interpolation   int `json:"interpolation"`
	SensitiveEmpty  int `json:"sensitive_empty"`
	CommandValue    int `json:"command_value"`
	DuplicateKey    int `json:"duplicate_key"`
	SensitiveInline int `json:"sensitive_inline"`
}

var shellMetaRe = regexp.MustCompile("[;|&`$]|\\$\\(")

var interpolationRe = regexp.MustCompile(`\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*`)

var commandPrefixes = []string{
	"bash ", "sh ", "/bin/", "/usr/bin/", "curl ", "wget ", "exec ", "eval ",
}

var sensitiveNames = []string{
	"PASSWORD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
	"PRIVATE_KEY", "ACCESS_KEY", "CREDENTIAL",
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	seen := map[string]int{}
	for i, env := range svc.Environment {
		key, val := splitEnv(env)
		upper := strings.ToUpper(key)

		if prev, ok := seen[upper]; ok {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "envinjection_duplicate_key",
				Message: fmt.Sprintf("Service '%s' has duplicate env var '%s' (indices %d and %d); last value wins", svc.Name, key, prev, i),
			})
		}
		seen[upper] = i

		isSensitive := false
		for _, s := range sensitiveNames {
			if strings.Contains(upper, s) {
				isSensitive = true
				break
			}
		}

		if isSensitive && val == "" {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "envinjection_sensitive_empty",
				Message: fmt.Sprintf("Service '%s' declares sensitive var '%s' with empty value; secret may be missing", svc.Name, key),
			})
		}

		if isSensitive && val != "" && !interpolationRe.MatchString(val) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "envinjection_sensitive_inline",
				Message: fmt.Sprintf("Service '%s' has sensitive var '%s' with inline value; use a secret or env_file", svc.Name, key),
			})
		}

		if val != "" && shellMetaRe.MatchString(val) && !interpolationRe.MatchString(val) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "envinjection_shell_metachar",
				Message: fmt.Sprintf("Service '%s' env var '%s' contains shell metacharacters; risk of injection if passed to shell", svc.Name, key),
			})
		}

		if val != "" && interpolationRe.MatchString(val) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "low",
				Rule:    "envinjection_interpolation",
				Message: fmt.Sprintf("Service '%s' env var '%s' uses variable interpolation; value depends on host environment", svc.Name, key),
			})
		}

		if val != "" && isCommandValue(val) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "envinjection_command_value",
				Message: fmt.Sprintf("Service '%s' env var '%s' value looks like a shell command; potential code execution", svc.Name, key),
			})
		}
	}

	return sr
}

func splitEnv(s string) (string, string) {
	idx := strings.IndexByte(s, '=')
	if idx < 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

func isCommandValue(val string) bool {
	lower := strings.ToLower(strings.TrimSpace(val))
	for _, prefix := range commandPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "envinjection_shell_metachar":
				s.ShellMetachar++
			case "envinjection_interpolation":
				s.Interpolation++
			case "envinjection_sensitive_empty":
				s.SensitiveEmpty++
			case "envinjection_command_value":
				s.CommandValue++
			case "envinjection_duplicate_key":
				s.DuplicateKey++
			case "envinjection_sensitive_inline":
				s.SensitiveInline++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Environment Injection Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Shell metacharacters:   %d\n", r.Summary.ShellMetachar)
	fmt.Fprintf(&b, "  Variable interpolation: %d\n", r.Summary.Interpolation)
	fmt.Fprintf(&b, "  Sensitive empty value:   %d\n", r.Summary.SensitiveEmpty)
	fmt.Fprintf(&b, "  Command-like value:     %d\n", r.Summary.CommandValue)
	fmt.Fprintf(&b, "  Duplicate keys:         %d\n", r.Summary.DuplicateKey)
	fmt.Fprintf(&b, "  Sensitive inline value:  %d\n\n", r.Summary.SensitiveInline)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s\n", sr.Service)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		if len(sr.Findings) == 0 {
			fmt.Fprintf(&b, "    (no findings)\n")
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
