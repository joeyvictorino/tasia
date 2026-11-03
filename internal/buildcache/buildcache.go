package buildcache

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

var (
	cacheMountRe = regexp.MustCompile(`(?i)--mount=type=cache(?:,([^"\s]+))?`)
	targetRe     = regexp.MustCompile(`(?i)target=([^\s,]+)`)
	uidRe        = regexp.MustCompile(`(?i)uid=(\d+)`)
)

var sensitivePaths = []string{
	"/root", "/home", "/etc", "/var/run", "/var/lib",
	"/tmp/secrets", ".ssh", ".gnupg", ".aws", ".config",
}

type Finding struct {
	File        string `json:"file"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Line        int    `json:"line"`
	Remediation string `json:"remediation"`
}

type CacheMount struct {
	Target string `json:"target"`
	Line   int    `json:"line"`
	UID    string `json:"uid,omitempty"`
}

type FileResult struct {
	Path        string       `json:"path"`
	CacheMounts []CacheMount `json:"cache_mounts,omitempty"`
	Findings    []Finding    `json:"findings,omitempty"`
}

type Summary struct {
	TotalFiles      int `json:"total_files"`
	FilesWithCache  int `json:"files_with_cache"`
	TotalMounts     int `json:"total_mounts"`
	TotalFindings   int `json:"total_findings"`
}

type Report struct {
	Files   []FileResult `json:"files"`
	Summary Summary      `json:"summary"`
}

func Analyze(collected *collect.Collected) Report {
	var files []FileResult
	var s Summary

	for _, df := range collected.Dockerfiles {
		s.TotalFiles++
		fr := FileResult{Path: df.Path}

		mounts := parseCacheMounts(df.Content)
		fr.CacheMounts = mounts
		s.TotalMounts += len(mounts)

		if len(mounts) > 0 {
			s.FilesWithCache++
		}

		fr.Findings = analyzeCacheSecurity(df, mounts)
		s.TotalFindings += len(fr.Findings)
		files = append(files, fr)
	}

	return Report{Files: files, Summary: s}
}

func parseCacheMounts(content string) []CacheMount {
	var mounts []CacheMount
	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		matches := cacheMountRe.FindAllStringSubmatch(trimmed, -1)
		for _, m := range matches {
			cm := CacheMount{Line: i + 1}
			opts := ""
			if len(m) > 1 {
				opts = m[1]
			}
			if tm := targetRe.FindStringSubmatch(opts); tm != nil {
				cm.Target = tm[1]
			}
			if um := uidRe.FindStringSubmatch(opts); um != nil {
				cm.UID = um[1]
			}
			mounts = append(mounts, cm)
		}
	}
	return mounts
}

func analyzeCacheSecurity(df collect.Dockerfile, mounts []CacheMount) []Finding {
	var findings []Finding

	for _, cm := range mounts {
		if cm.Target == "" {
			findings = append(findings, Finding{
				File:        df.Path,
				RuleID:      "cache_no_target",
				Severity:    "low",
				Detail:      "Cache mount has no explicit target path; default location may be unpredictable",
				Line:        cm.Line,
				Remediation: "Specify target= for cache mounts to control where cached data is stored",
			})
			continue
		}

		for _, sp := range sensitivePaths {
			if strings.HasPrefix(cm.Target, sp) || cm.Target == sp {
				findings = append(findings, Finding{
					File:        df.Path,
					RuleID:      "cache_sensitive_path",
					Severity:    "high",
					Detail:      fmt.Sprintf("Cache mount targets sensitive path %q; cached data persists across builds and may leak secrets", cm.Target),
					Line:        cm.Line,
					Remediation: "Use a non-sensitive cache directory (e.g. /var/cache/buildkit) and avoid caching credential directories",
				})
				break
			}
		}

		if cm.UID == "0" {
			findings = append(findings, Finding{
				File:        df.Path,
				RuleID:      "cache_root_uid",
				Severity:    "medium",
				Detail:      fmt.Sprintf("Cache mount at %s uses uid=0 (root); other builds sharing this cache can inject files owned by root", cm.Target),
				Line:        cm.Line,
				Remediation: "Use a non-root uid for cache mounts to limit cross-build file injection risk",
			})
		}
	}

	if len(mounts) > 0 {
		lines := strings.Split(df.Content, "\n")
		hasCleanup := false
		for _, line := range lines {
			trimmed := strings.ToLower(strings.TrimSpace(line))
			if strings.Contains(trimmed, "rm -rf") && strings.Contains(trimmed, "cache") {
				hasCleanup = true
				break
			}
			if strings.Contains(trimmed, "apt-get clean") || strings.Contains(trimmed, "pip cache purge") || strings.Contains(trimmed, "npm cache clean") {
				hasCleanup = true
				break
			}
		}
		_ = hasCleanup
	}

	lines := strings.Split(df.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "--mount=type=cache") && strings.Contains(lower, "pip install") && !strings.Contains(lower, "--no-cache-dir") {
			findings = append(findings, Finding{
				File:        df.Path,
				RuleID:      "cache_pip_no_nocache",
				Severity:    "low",
				Detail:      "pip install with cache mount but no --no-cache-dir; pip's internal cache may duplicate the mount cache",
				Line:        i + 1,
				Remediation: "Add --no-cache-dir to pip install when using a BuildKit cache mount",
			})
		}
	}

	return findings
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Build Cache Security Analysis\n")
	b.WriteString(strings.Repeat("=", 62) + "\n\n")

	fmt.Fprintf(&b, "  Dockerfiles scanned:   %d\n", r.Summary.TotalFiles)
	fmt.Fprintf(&b, "  Files with cache:      %d\n", r.Summary.FilesWithCache)
	fmt.Fprintf(&b, "  Total cache mounts:    %d\n", r.Summary.TotalMounts)
	fmt.Fprintf(&b, "  Total findings:        %d\n\n", r.Summary.TotalFindings)

	for _, fr := range r.Files {
		if len(fr.CacheMounts) == 0 && len(fr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s\n", fr.Path)
		for _, cm := range fr.CacheMounts {
			target := cm.Target
			if target == "" {
				target = "(default)"
			}
			fmt.Fprintf(&b, "    cache mount @ line %d: target=%s\n", cm.Line, target)
		}
		for _, f := range fr.Findings {
			sev := strings.ToUpper(f.Severity)
			if f.Line > 0 {
				fmt.Fprintf(&b, "    [%s] line %d: %s (%s)\n", sev, f.Line, f.Detail, f.RuleID)
			} else {
				fmt.Fprintf(&b, "    [%s] %s (%s)\n", sev, f.Detail, f.RuleID)
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}
