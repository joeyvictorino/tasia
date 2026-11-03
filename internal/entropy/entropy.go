package entropy

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type Finding struct {
	Service  string  `json:"service"`
	Source   string  `json:"source"`
	Key      string  `json:"key"`
	Entropy  float64 `json:"entropy"`
	Length   int     `json:"length"`
	Severity string  `json:"severity"`
	Reason   string  `json:"reason"`
	Line     int     `json:"line"`
}

type Report struct {
	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
}

type Summary struct {
	TotalEnvVars     int            `json:"total_env_vars"`
	HighEntropyCount int            `json:"high_entropy_count"`
	BySeverity       map[string]int `json:"by_severity"`
	ByService        map[string]int `json:"by_service"`
}

const (
	DefaultThreshold = 3.5
	HighThreshold    = 4.0
	MinValueLength   = 8
)

var knownSafeValues = map[string]bool{
	"true": true, "false": true, "yes": true, "no": true,
	"on": true, "off": true, "enabled": true, "disabled": true,
	"production": true, "development": true, "staging": true, "test": true,
	"debug": true, "info": true, "warn": true, "error": true,
	"localhost": true, "0.0.0.0": true, "127.0.0.1": true,
	"utf-8": true, "utf8": true, "ascii": true,
}

var knownSafeKeyPrefixes = []string{
	"LOG_", "NODE_ENV", "PYTHONPATH", "GOPATH", "PATH",
	"TZ", "LANG", "LC_", "HOME", "USER", "SHELL",
	"PORT", "HOST", "HOSTNAME", "DATABASE",
}

func Shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	ent := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			ent -= p * math.Log2(p)
		}
	}
	return math.Round(ent*100) / 100
}

func Analyze(col *collect.Collected, threshold float64) Report {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}

	var findings []Finding
	totalVars := 0

	for _, cf := range col.ComposeFiles {
		for _, svc := range cf.Services {
			for _, env := range svc.Environment {
				totalVars++
				f := analyzeEnvEntry(svc.Name, cf.Path, svc.EnvLine, env, threshold)
				if f != nil {
					findings = append(findings, *f)
				}
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Entropy > findings[j].Entropy
	})

	return Report{
		Findings: findings,
		Summary:  buildSummary(findings, totalVars),
	}
}

func analyzeEnvEntry(service, source string, baseLine int, entry string, threshold float64) *Finding {
	idx := strings.Index(entry, "=")
	if idx <= 0 {
		return nil
	}
	key := strings.TrimSpace(entry[:idx])
	val := strings.TrimSpace(entry[idx+1:])

	if len(val) < MinValueLength {
		return nil
	}

	lower := strings.ToLower(val)
	if knownSafeValues[lower] {
		return nil
	}

	if isSafeKey(key) {
		return nil
	}

	ent := Shannon(val)
	if ent < threshold {
		return nil
	}

	sev := "medium"
	reason := fmt.Sprintf("high entropy value (%.2f bits)", ent)
	if ent >= HighThreshold {
		sev = "high"
		reason = fmt.Sprintf("very high entropy value (%.2f bits)", ent)
	}
	if collect.LooksLikeSecretKeyName(key) {
		if sev == "medium" {
			sev = "high"
		} else {
			sev = "critical"
		}
		reason += "; key name suggests a secret"
	}
	if collect.LooksLikeSecretValue(val) != "" {
		sev = "critical"
		reason += "; value matches known secret pattern"
	}

	return &Finding{
		Service:  service,
		Source:   source,
		Key:      key,
		Entropy:  ent,
		Length:   len(val),
		Severity: sev,
		Reason:   reason,
		Line:     baseLine,
	}
}

func isSafeKey(key string) bool {
	upper := strings.ToUpper(key)
	for _, prefix := range knownSafeKeyPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

func buildSummary(findings []Finding, totalVars int) Summary {
	bySev := map[string]int{}
	bySvc := map[string]int{}
	for _, f := range findings {
		bySev[f.Severity]++
		bySvc[f.Service]++
	}
	return Summary{
		TotalEnvVars:     totalVars,
		HighEntropyCount: len(findings),
		BySeverity:       bySev,
		ByService:        bySvc,
	}
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Environment Variable Entropy Analysis\n")
	b.WriteString(strings.Repeat("=", 62) + "\n\n")
	b.WriteString(fmt.Sprintf("  Total env vars scanned: %d\n", r.Summary.TotalEnvVars))
	b.WriteString(fmt.Sprintf("  High-entropy findings:  %d\n\n", r.Summary.HighEntropyCount))

	if len(r.Findings) == 0 {
		b.WriteString("  No high-entropy values detected.\n")
		return b.String()
	}

	b.WriteString(fmt.Sprintf("  %-12s %-20s %-25s %8s %8s\n", "Severity", "Service", "Key", "Entropy", "Length"))
	b.WriteString("  " + strings.Repeat("-", 76) + "\n")
	for _, f := range r.Findings {
		svc := truncate(f.Service, 20)
		key := truncate(f.Key, 25)
		b.WriteString(fmt.Sprintf("  %-12s %-20s %-25s %8.2f %8d\n",
			strings.ToUpper(f.Severity), svc, key, f.Entropy, f.Length))
	}
	b.WriteByte('\n')

	if len(r.Summary.BySeverity) > 0 {
		b.WriteString("  By Severity:\n")
		sevOrder := []string{"critical", "high", "medium", "low"}
		for _, s := range sevOrder {
			if c, ok := r.Summary.BySeverity[s]; ok {
				b.WriteString(fmt.Sprintf("    %-10s %d\n", strings.ToUpper(s), c))
			}
		}
		b.WriteByte('\n')
	}

	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
