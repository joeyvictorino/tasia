package envexpand

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
	TotalServices        int `json:"total_services"`
	TotalFindings        int `json:"total_findings"`
	ShellExpansion       int `json:"shell_expansion"`
	BacktickInjection    int `json:"backtick_injection"`
	NestedInterpolation  int `json:"nested_interpolation"`
	EmptyDefault         int `json:"empty_default"`
	SecretInEnv          int `json:"secret_in_env"`
	UnquotedExpansion    int `json:"unquoted_expansion"`
}

var (
	shellExpansionRE    = regexp.MustCompile(`\$\(.*\)`)
	backtickRE          = regexp.MustCompile("`[^`]+`")
	nestedInterpRE      = regexp.MustCompile(`\$\{[^}]*\$\{`)
	emptyDefaultRE      = regexp.MustCompile(`\$\{[A-Z_]+:-\}`)
	secretKeyRE         = regexp.MustCompile(`(?i)(password|secret|token|api_key|apikey|private_key|access_key|auth_token|credentials?)=.+`)
	unquotedDollarRE    = regexp.MustCompile(`\$\{[A-Z_]+\}`)
)

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

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) < 2 {
			continue
		}
		key := parts[0]
		val := parts[1]

		if shellExpansionRE.MatchString(val) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "envexpand_shell_expansion",
				Message: fmt.Sprintf("Service '%s' env var '%s' contains shell command expansion $(); may allow command injection", svc.Name, key),
			})
		}

		if backtickRE.MatchString(val) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "envexpand_backtick_injection",
				Message: fmt.Sprintf("Service '%s' env var '%s' contains backtick command substitution; may allow command injection", svc.Name, key),
			})
		}

		if nestedInterpRE.MatchString(val) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "envexpand_nested_interpolation",
				Message: fmt.Sprintf("Service '%s' env var '%s' contains nested variable interpolation; may cause unexpected expansion", svc.Name, key),
			})
		}

		if emptyDefaultRE.MatchString(val) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "envexpand_empty_default",
				Message: fmt.Sprintf("Service '%s' env var '%s' uses empty default value ${VAR:-}; may silently produce empty config", svc.Name, key),
			})
		}

		if secretKeyRE.MatchString(env) && !unquotedDollarRE.MatchString(val) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "envexpand_secret_in_env",
				Message: fmt.Sprintf("Service '%s' env var '%s' appears to contain a hardcoded secret value", svc.Name, key),
			})
		}

		dollarCount := strings.Count(val, "${")
		if dollarCount >= 3 {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "envexpand_unquoted_expansion",
				Message: fmt.Sprintf("Service '%s' env var '%s' has %d variable expansions; complex interpolation is fragile and hard to audit", svc.Name, key, dollarCount),
			})
		}
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "envexpand_shell_expansion":
				s.ShellExpansion++
			case "envexpand_backtick_injection":
				s.BacktickInjection++
			case "envexpand_nested_interpolation":
				s.NestedInterpolation++
			case "envexpand_empty_default":
				s.EmptyDefault++
			case "envexpand_secret_in_env":
				s.SecretInEnv++
			case "envexpand_unquoted_expansion":
				s.UnquotedExpansion++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Environment Variable Expansion Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Shell expansion:       %d\n", r.Summary.ShellExpansion)
	fmt.Fprintf(&b, "  Backtick injection:    %d\n", r.Summary.BacktickInjection)
	fmt.Fprintf(&b, "  Nested interpolation:  %d\n", r.Summary.NestedInterpolation)
	fmt.Fprintf(&b, "  Empty defaults:        %d\n", r.Summary.EmptyDefault)
	fmt.Fprintf(&b, "  Secrets in env:        %d\n", r.Summary.SecretInEnv)
	fmt.Fprintf(&b, "  Complex expansions:    %d\n\n", r.Summary.UnquotedExpansion)
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
