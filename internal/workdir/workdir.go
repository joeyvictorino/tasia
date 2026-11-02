package workdir

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

var tmpPaths = map[string]bool{
	"/tmp": true, "/var/tmp": true, "/dev/shm": true,
}

var rootPaths = map[string]bool{
	"/": true, "/root": true,
}

type Finding struct {
	File        string `json:"file"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Line        int    `json:"line"`
	Remediation string `json:"remediation"`
}

type FileResult struct {
	Path     string    `json:"path"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalFiles       int `json:"total_files"`
	WithWorkdir      int `json:"with_workdir"`
	MissingWorkdir   int `json:"missing_workdir"`
	TmpWorkdir       int `json:"tmp_workdir"`
	RootWorkdir      int `json:"root_workdir"`
	TotalFindings    int `json:"total_findings"`
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

		if len(df.Workdirs) == 0 {
			s.MissingWorkdir++
			fr.Findings = append(fr.Findings, Finding{
				File:        df.Path,
				RuleID:      "workdir_missing",
				Severity:    "low",
				Detail:      "Dockerfile has no WORKDIR directive; defaults to / which may expose sensitive host paths",
				Remediation: "Add WORKDIR /app or similar to set a dedicated working directory",
			})
		} else {
			s.WithWorkdir++
		}

		for _, wd := range df.Workdirs {
			path := wd.Path
			if path != "/" {
				path = strings.TrimRight(path, "/")
			}
			if tmpPaths[path] {
				s.TmpWorkdir++
				fr.Findings = append(fr.Findings, Finding{
					File:        df.Path,
					RuleID:      "workdir_tmp",
					Severity:    "medium",
					Detail:      fmt.Sprintf("WORKDIR set to %s; world-writable temp directories risk data exposure and race conditions", wd.Path),
					Line:        wd.Line,
					Remediation: "Use a dedicated application directory like /app or /opt/app",
				})
			}
			if rootPaths[path] {
				s.RootWorkdir++
				fr.Findings = append(fr.Findings, Finding{
					File:        df.Path,
					RuleID:      "workdir_root",
					Severity:    "medium",
					Detail:      fmt.Sprintf("WORKDIR set to %s; working in root directories risks overwriting system files", wd.Path),
					Line:        wd.Line,
					Remediation: "Use a dedicated application directory like /app or /opt/app",
				})
			}
			if !strings.HasPrefix(wd.Path, "/") && !strings.HasPrefix(wd.Path, "$") {
				fr.Findings = append(fr.Findings, Finding{
					File:        df.Path,
					RuleID:      "workdir_relative",
					Severity:    "low",
					Detail:      fmt.Sprintf("WORKDIR uses relative path %q; resolved path depends on parent image and may be unpredictable", wd.Path),
					Line:        wd.Line,
					Remediation: "Use an absolute path for WORKDIR",
				})
			}
		}

		s.TotalFindings += len(fr.Findings)
		files = append(files, fr)
	}

	return Report{Files: files, Summary: s}
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("WORKDIR Security Analysis\n")
	b.WriteString(strings.Repeat("=", 62) + "\n\n")

	fmt.Fprintf(&b, "  Dockerfiles scanned:   %d\n", r.Summary.TotalFiles)
	fmt.Fprintf(&b, "  With WORKDIR:          %d\n", r.Summary.WithWorkdir)
	fmt.Fprintf(&b, "  Missing WORKDIR:       %d\n", r.Summary.MissingWorkdir)
	fmt.Fprintf(&b, "  Tmp directory WORKDIR: %d\n", r.Summary.TmpWorkdir)
	fmt.Fprintf(&b, "  Root path WORKDIR:     %d\n", r.Summary.RootWorkdir)
	fmt.Fprintf(&b, "  Total findings:        %d\n\n", r.Summary.TotalFindings)

	for _, fr := range r.Files {
		if len(fr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s\n", fr.Path)
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
