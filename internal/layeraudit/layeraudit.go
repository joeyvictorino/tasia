package layeraudit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type Severity string

const (
	SevHigh   Severity = "high"
	SevMedium Severity = "medium"
	SevLow    Severity = "low"
)

type Finding struct {
	File     string   `json:"file"`
	Line     int      `json:"line,omitempty"`
	Severity Severity `json:"severity"`
	Rule     string   `json:"rule"`
	Message  string   `json:"message"`
}

type FileReport struct {
	File       string    `json:"file"`
	RunCount   int       `json:"run_count"`
	LayerCount int       `json:"layer_count"`
	Findings   []Finding `json:"findings,omitempty"`
}

type Report struct {
	Files    []FileReport `json:"files"`
	Total    int          `json:"total_findings"`
	ByRule   map[string]int `json:"by_rule"`
}

func Analyze(collected collect.Collected) Report {
	var files []FileReport
	byRule := map[string]int{}

	for _, df := range collected.Dockerfiles {
		fr := analyzeDockerfile(df)
		for _, f := range fr.Findings {
			byRule[f.Rule]++
		}
		files = append(files, fr)
	}

	sort.Slice(files, func(i, j int) bool {
		return len(files[i].Findings) > len(files[j].Findings)
	})

	total := 0
	for _, f := range files {
		total += len(f.Findings)
	}

	return Report{Files: files, Total: total, ByRule: byRule}
}

func analyzeDockerfile(df collect.Dockerfile) FileReport {
	lines := strings.Split(df.Content, "\n")
	var findings []Finding
	var runLines []int
	runCount := 0
	layerCount := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)

		if strings.HasPrefix(upper, "RUN ") || strings.HasPrefix(upper, "COPY ") || strings.HasPrefix(upper, "ADD ") {
			layerCount++
		}

		if strings.HasPrefix(upper, "RUN ") {
			runCount++
			runLines = append(runLines, i+1)
		}
	}

	if runCount > 10 {
		findings = append(findings, Finding{
			File:     df.Path,
			Severity: SevMedium,
			Rule:     "excessive_run",
			Message:  fmt.Sprintf("%d RUN instructions; consider combining with && to reduce layers", runCount),
		})
	}

	findings = append(findings, checkConsecutiveRuns(df.Path, lines)...)
	findings = append(findings, checkMissingCleanup(df.Path, lines)...)
	findings = append(findings, checkAddURL(df)...)
	findings = append(findings, checkCurlNoPipe(df.Path, lines)...)
	findings = append(findings, checkPipInstallNoCache(df.Path, lines)...)

	sort.Slice(findings, func(i, j int) bool {
		return sevRank(findings[i].Severity) > sevRank(findings[j].Severity)
	})

	return FileReport{
		File:       df.Path,
		RunCount:   runCount,
		LayerCount: layerCount,
		Findings:   findings,
	}
}

func checkConsecutiveRuns(file string, lines []string) []Finding {
	var findings []Finding
	consecutive := 0
	startLine := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "RUN ") {
			if consecutive == 0 {
				startLine = i + 1
			}
			consecutive++
		} else if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasSuffix(trimmed, "\\") {
			if consecutive >= 3 {
				findings = append(findings, Finding{
					File:     file,
					Line:     startLine,
					Severity: SevLow,
					Rule:     "consecutive_run",
					Message:  fmt.Sprintf("%d consecutive RUN instructions starting at line %d; combine with &&", consecutive, startLine),
				})
			}
			consecutive = 0
		}
	}
	if consecutive >= 3 {
		findings = append(findings, Finding{
			File:     file,
			Line:     startLine,
			Severity: SevLow,
			Rule:     "consecutive_run",
			Message:  fmt.Sprintf("%d consecutive RUN instructions starting at line %d; combine with &&", consecutive, startLine),
		})
	}
	return findings
}

func checkMissingCleanup(file string, lines []string) []Finding {
	var findings []Finding
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "apt-get install") || strings.Contains(lower, "apt install") {
			fullCmd := gatherMultiline(lines, i)
			if !strings.Contains(fullCmd, "rm -rf /var/lib/apt") && !strings.Contains(fullCmd, "apt-get clean") {
				findings = append(findings, Finding{
					File:     file,
					Line:     i + 1,
					Severity: SevMedium,
					Rule:     "apt_no_cleanup",
					Message:  "apt-get install without cleanup (rm -rf /var/lib/apt/lists/* or apt-get clean)",
				})
			}
		}
		if strings.Contains(lower, "pip install") && !strings.Contains(lower, "--no-cache-dir") {
			findings = append(findings, Finding{
				File:     file,
				Line:     i + 1,
				Severity: SevLow,
				Rule:     "pip_no_cache_dir",
				Message:  "pip install without --no-cache-dir wastes layer space",
			})
		}
	}
	return findings
}

func checkAddURL(df collect.Dockerfile) []Finding {
	var findings []Finding
	for _, add := range df.Adds {
		if add.IsURL {
			findings = append(findings, Finding{
				File:     df.Path,
				Line:     add.Line,
				Severity: SevHigh,
				Rule:     "add_url",
				Message:  fmt.Sprintf("ADD from URL %q; use RUN curl/wget instead for cache control and verification", add.Source),
			})
		}
	}
	return findings
}

func checkCurlNoPipe(file string, lines []string) []Finding {
	var findings []Finding
	for i, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(lower, "curl") && strings.Contains(lower, "| sh") || strings.Contains(lower, "| bash") {
			findings = append(findings, Finding{
				File:     file,
				Line:     i + 1,
				Severity: SevHigh,
				Rule:     "curl_pipe_shell",
				Message:  "curl piped to shell (| sh or | bash); verify script integrity with checksums",
			})
		}
	}
	return findings
}

func checkPipInstallNoCache(file string, lines []string) []Finding {
	return nil
}

func gatherMultiline(lines []string, start int) string {
	var parts []string
	for i := start; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		parts = append(parts, trimmed)
		if !strings.HasSuffix(trimmed, "\\") {
			break
		}
	}
	return strings.Join(parts, " ")
}

func sevRank(s Severity) int {
	switch s {
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	}
	return 0
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Dockerfile Layer Audit  (%d findings across %d files)\n", r.Total, len(r.Files))
	b.WriteString(strings.Repeat("=", 60) + "\n\n")

	for _, f := range r.Files {
		fmt.Fprintf(&b, "  %s  (RUN=%d, layers=%d, findings=%d)\n", f.File, f.RunCount, f.LayerCount, len(f.Findings))
		for _, fi := range f.Findings {
			if fi.Line > 0 {
				fmt.Fprintf(&b, "    [%s] line %d: %s (%s)\n", fi.Severity, fi.Line, fi.Message, fi.Rule)
			} else {
				fmt.Fprintf(&b, "    [%s] %s (%s)\n", fi.Severity, fi.Message, fi.Rule)
			}
		}
		b.WriteString("\n")
	}

	if len(r.ByRule) > 0 {
		b.WriteString("  By rule:\n")
		for rule, count := range r.ByRule {
			fmt.Fprintf(&b, "    %-25s %d\n", rule, count)
		}
	}
	return b.String()
}
