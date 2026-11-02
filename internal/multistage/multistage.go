package multistage

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

var (
	fromRe     = regexp.MustCompile(`(?i)^FROM\s+(\S+)(?:\s+AS\s+(\S+))?`)
	copyFromRe = regexp.MustCompile(`(?i)^COPY\s+--from=(\S+)\s+(.+)`)
	runMountRe = regexp.MustCompile(`(?i)--mount=type=secret`)
)

type Stage struct {
	Image string
	Alias string
	Line  int
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
	Stages   []Stage   `json:"stages"`
	Findings []Finding `json:"findings,omitempty"`
}

type Summary struct {
	TotalFiles        int `json:"total_files"`
	MultiStageFiles   int `json:"multi_stage_files"`
	SingleStageFiles  int `json:"single_stage_files"`
	TotalStages       int `json:"total_stages"`
	TotalFindings     int `json:"total_findings"`
}

type Report struct {
	Files   []FileResult `json:"files"`
	Summary Summary      `json:"summary"`
}

var dangerousBase = map[string]bool{
	"ubuntu": true, "debian": true, "centos": true, "fedora": true,
	"amazonlinux": true, "archlinux": true, "oraclelinux": true,
}

var buildToolPatterns = []string{
	"gcc", "g++", "make", "cmake", "cargo", "rustc", "npm", "yarn",
	"pip", "poetry", "go build", "javac", "mvn", "gradle",
}

func Analyze(collected *collect.Collected) Report {
	var files []FileResult
	var s Summary

	for _, df := range collected.Dockerfiles {
		s.TotalFiles++
		fr := FileResult{Path: df.Path}

		stages := parseStages(df.Content)
		fr.Stages = stages
		s.TotalStages += len(stages)

		if len(stages) <= 1 {
			s.SingleStageFiles++
			files = append(files, fr)
			continue
		}

		s.MultiStageFiles++

		fr.Findings = analyzeMultiStage(df, stages)
		s.TotalFindings += len(fr.Findings)
		files = append(files, fr)
	}

	return Report{Files: files, Summary: s}
}

func parseStages(content string) []Stage {
	var stages []Stage
	for i, line := range strings.Split(content, "\n") {
		m := fromRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		st := Stage{Image: m[1], Line: i + 1}
		if len(m) > 2 {
			st.Alias = m[2]
		}
		stages = append(stages, st)
	}
	return stages
}

func analyzeMultiStage(df collect.Dockerfile, stages []Stage) []Finding {
	var findings []Finding
	lines := strings.Split(df.Content, "\n")

	finalStage := stages[len(stages)-1]

	baseImg := strings.Split(finalStage.Image, ":")[0]
	baseImg = strings.Split(baseImg, "@")[0]
	parts := strings.Split(baseImg, "/")
	shortName := parts[len(parts)-1]
	if dangerousBase[strings.ToLower(shortName)] {
		findings = append(findings, Finding{
			File:        df.Path,
			RuleID:      "multistage_fat_final",
			Severity:    "medium",
			Detail:      fmt.Sprintf("Final stage uses full OS image %q; prefer a minimal base like alpine or distroless", finalStage.Image),
			Line:        finalStage.Line,
			Remediation: "Use a minimal base image (alpine, distroless, scratch) for the final stage",
		})
	}

	stageAliases := map[string]bool{}
	for _, st := range stages {
		if st.Alias != "" {
			stageAliases[strings.ToLower(st.Alias)] = true
		}
	}

	finalStart := stages[len(stages)-1].Line - 1
	for i := finalStart; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		m := copyFromRe.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		source := m[1]
		sourceLower := strings.ToLower(source)
		if !stageAliases[sourceLower] {
			isStageIndex := true
			for _, c := range source {
				if c < '0' || c > '9' {
					isStageIndex = false
					break
				}
			}
			if !isStageIndex {
				findings = append(findings, Finding{
					File:        df.Path,
					RuleID:      "multistage_external_copy",
					Severity:    "high",
					Detail:      fmt.Sprintf("COPY --from=%s references an external image, not a build stage; contents are unvetted", source),
					Line:        i + 1,
					Remediation: "Copy from a named build stage or pin the external image with a digest",
				})
			}
		}
	}

	for idx, st := range stages[:len(stages)-1] {
		if !strings.Contains(st.Image, "@sha256:") && !strings.Contains(st.Image, ":") {
			findings = append(findings, Finding{
				File:        df.Path,
				RuleID:      "multistage_unpinned_builder",
				Severity:    "medium",
				Detail:      fmt.Sprintf("Builder stage %d (%s) uses unpinned image %q; supply-chain risk", idx, st.Alias, st.Image),
				Line:        st.Line,
				Remediation: "Pin builder images with a specific tag or digest",
			})
		}
	}

	finalHasBuildTools := false
	for i := finalStart; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "RUN ") {
			for _, tool := range buildToolPatterns {
				if strings.Contains(strings.ToLower(trimmed), tool) {
					finalHasBuildTools = true
					findings = append(findings, Finding{
						File:        df.Path,
						RuleID:      "multistage_build_tools_final",
						Severity:    "medium",
						Detail:      fmt.Sprintf("Final stage runs build tool %q; build tools in production increase attack surface", tool),
						Line:        i + 1,
						Remediation: "Move build steps to an earlier stage and COPY only artifacts to the final stage",
					})
					break
				}
			}
		}
	}
	_ = finalHasBuildTools

	hasSecretMount := false
	for i := finalStart; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if runMountRe.MatchString(trimmed) {
			hasSecretMount = true
			findings = append(findings, Finding{
				File:        df.Path,
				RuleID:      "multistage_secret_final",
				Severity:    "high",
				Detail:      "Final stage uses --mount=type=secret; secrets in the final image may leak at runtime",
				Line:        i + 1,
				Remediation: "Mount secrets only in builder stages; copy only the built artifacts to the final stage",
			})
		}
	}
	_ = hasSecretMount

	if df.User == "" {
		findings = append(findings, Finding{
			File:        df.Path,
			RuleID:      "multistage_root_final",
			Severity:    "medium",
			Detail:      "Multi-stage Dockerfile runs final stage as root (no USER directive)",
			Remediation: "Add USER nonroot or USER nobody in the final stage",
		})
	}

	return findings
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Multi-Stage Build Security Analysis\n")
	b.WriteString(strings.Repeat("=", 62) + "\n\n")

	fmt.Fprintf(&b, "  Dockerfiles scanned:     %d\n", r.Summary.TotalFiles)
	fmt.Fprintf(&b, "  Multi-stage Dockerfiles: %d\n", r.Summary.MultiStageFiles)
	fmt.Fprintf(&b, "  Single-stage:            %d\n", r.Summary.SingleStageFiles)
	fmt.Fprintf(&b, "  Total stages:            %d\n", r.Summary.TotalStages)
	fmt.Fprintf(&b, "  Total findings:          %d\n\n", r.Summary.TotalFindings)

	for _, fr := range r.Files {
		if len(fr.Findings) == 0 && len(fr.Stages) <= 1 {
			continue
		}
		fmt.Fprintf(&b, "  %s (%d stages)\n", fr.Path, len(fr.Stages))
		for _, st := range fr.Stages {
			alias := ""
			if st.Alias != "" {
				alias = " AS " + st.Alias
			}
			fmt.Fprintf(&b, "    stage @ line %d: %s%s\n", st.Line, st.Image, alias)
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
