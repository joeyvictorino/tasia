package copyadd

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

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
	TotalFiles    int `json:"total_files"`
	AddFromURL    int `json:"add_from_url"`
	AddArchive    int `json:"add_archive"`
	TotalFindings int `json:"total_findings"`
}

type Report struct {
	Files   []FileResult `json:"files"`
	Summary Summary      `json:"summary"`
}

var archiveExtensions = []string{".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip"}

func isArchive(src string) bool {
	lower := strings.ToLower(src)
	for _, ext := range archiveExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func Analyze(collected *collect.Collected) Report {
	var files []FileResult
	var s Summary

	for _, df := range collected.Dockerfiles {
		s.TotalFiles++
		fr := FileResult{Path: df.Path}

		for _, add := range df.Adds {
			if add.IsURL {
				s.AddFromURL++
				fr.Findings = append(fr.Findings, Finding{
					File:        df.Path,
					RuleID:      "add_url",
					Severity:    "high",
					Detail:      fmt.Sprintf("ADD fetches from URL %s; remote content is unverified and may be tampered with", add.Source),
					Line:        add.Line,
					Remediation: "Use COPY with a locally verified file, or use curl/wget in a RUN step with checksum verification",
				})
			}
			if isArchive(add.Source) && !add.IsURL {
				s.AddArchive++
				fr.Findings = append(fr.Findings, Finding{
					File:        df.Path,
					RuleID:      "add_archive",
					Severity:    "medium",
					Detail:      fmt.Sprintf("ADD auto-extracts archive %s; extraction may overwrite files or create unexpected directory structures", add.Source),
					Line:        add.Line,
					Remediation: "Use COPY and explicit RUN tar xf for controlled extraction, or verify archive contents in CI",
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
	b.WriteString("COPY/ADD Security Analysis\n")
	b.WriteString(strings.Repeat("=", 62) + "\n\n")

	fmt.Fprintf(&b, "  Dockerfiles scanned: %d\n", r.Summary.TotalFiles)
	fmt.Fprintf(&b, "  ADD from URL:        %d\n", r.Summary.AddFromURL)
	fmt.Fprintf(&b, "  ADD with archive:    %d\n", r.Summary.AddArchive)
	fmt.Fprintf(&b, "  Total findings:      %d\n\n", r.Summary.TotalFindings)

	for _, fr := range r.Files {
		if len(fr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s\n", fr.Path)
		for _, f := range fr.Findings {
			sev := strings.ToUpper(f.Severity)
			fmt.Fprintf(&b, "    [%s] line %d: %s (%s)\n", sev, f.Line, f.Detail, f.RuleID)
		}
		b.WriteString("\n")
	}

	return b.String()
}
