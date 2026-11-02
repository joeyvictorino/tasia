package credleak

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
	TotalServices int `json:"total_services"`
	TotalFindings int `json:"total_findings"`
	LeakyServices int `json:"leaky_services"`
}

var credPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*\S+`),
	regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+`),
	regexp.MustCompile(`(?i)(secret[_-]?key|secret)\s*[=:]\s*\S+`),
	regexp.MustCompile(`(?i)(access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*\S+`),
	regexp.MustCompile(`(?i)(aws[_-]?secret[_-]?\w*|aws[_-]?access[_-]?key[_-]?\w*)\s*[=:]\s*\S+`),
	regexp.MustCompile(`(?i)(private[_-]?key|ssh[_-]?key)\s*[=:]\s*\S+`),
	regexp.MustCompile(`(?i)(database[_-]?url|db[_-]?password|db[_-]?pass)\s*[=:]\s*\S+`),
	regexp.MustCompile(`(?i)(github[_-]?token|gh[_-]?token|gitlab[_-]?token)\s*[=:]\s*\S+`),
}

var safeValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\$\{[^}]+\}`),
	regexp.MustCompile(`\$[A-Z_]+`),
	regexp.MustCompile(`^\s*$`),
}

func isSafeValue(val string) bool {
	val = strings.TrimSpace(val)
	if val == "" {
		return true
	}
	for _, p := range safeValuePatterns {
		if p.MatchString(val) {
			return true
		}
	}
	return false
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

	for _, env := range svc.Environment {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		val := parts[1]
		if isSafeValue(val) {
			continue
		}
		for _, pat := range credPatterns {
			if pat.MatchString(env) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "credleak_env_hardcoded",
					Message: fmt.Sprintf("Service '%s' has hardcoded credential in environment variable '%s'", svc.Name, key),
				})
				break
			}
		}
	}

	for _, cmd := range svc.Command {
		for _, pat := range credPatterns {
			if pat.MatchString(cmd) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "credleak_command_secret",
					Message: fmt.Sprintf("Service '%s' has credential pattern in command argument", svc.Name),
				})
				break
			}
		}
	}

	for k, v := range svc.Labels {
		if isSafeValue(v) {
			continue
		}
		entry := k + "=" + v
		for _, pat := range credPatterns {
			if pat.MatchString(entry) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "credleak_label_secret",
					Message: fmt.Sprintf("Service '%s' has credential pattern in label", svc.Name),
				})
				break
			}
		}
	}

	return sr
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Credential Leak Detection (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Services with leaks: %d\n\n", r.Summary.LeakyServices)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s  findings: %d\n", sr.Service, len(sr.Findings))
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

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, svc := range services {
		s.TotalFindings += len(svc.Findings)
		if len(svc.Findings) > 0 {
			s.LeakyServices++
		}
	}
	return s
}
