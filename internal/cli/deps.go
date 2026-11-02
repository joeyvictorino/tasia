package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type depEntry struct {
	Image     string `json:"image"`
	Tag       string `json:"tag"`
	Service   string `json:"service"`
	File      string `json:"file"`
	IsLatest  bool   `json:"is_latest"`
	IsDigest  bool   `json:"is_digest"`
	HasNoTag  bool   `json:"has_no_tag"`
	RiskLevel string `json:"risk_level"`
	Advice    string `json:"advice"`
}

type depsResult struct {
	Path    string     `json:"path"`
	Total   int        `json:"total"`
	Risky   int        `json:"risky"`
	Pinned  int        `json:"pinned"`
	Entries []depEntry `json:"entries"`
}

var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func runDeps(args []string) error {
	fs := flag.NewFlagSet("deps", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	var entries []depEntry

	for _, cf := range collected.ComposeFiles {
		relFile := cf.Path
		for _, svc := range cf.Services {
			if svc.Image == "" {
				continue
			}
			img, tag := parseImageRef(svc.Image)
			e := depEntry{
				Image:   img,
				Tag:     tag,
				Service: svc.Name,
				File:    relFile,
			}
			e.IsLatest = tag == "latest"
			e.IsDigest = digestRe.MatchString(tag)
			e.HasNoTag = tag == ""
			e.RiskLevel, e.Advice = assessDep(e)
			entries = append(entries, e)
		}
	}

	risky := 0
	pinned := 0
	for _, e := range entries {
		if e.RiskLevel == "high" || e.RiskLevel == "critical" {
			risky++
		}
		if e.IsDigest || (!e.IsLatest && !e.HasNoTag && isSemverTag(e.Tag)) {
			pinned++
		}
	}

	result := depsResult{
		Path:    absPath,
		Total:   len(entries),
		Risky:   risky,
		Pinned:  pinned,
		Entries: entries,
	}

	switch *format {
	case "json":
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	default:
		printDeps(result)
	}
	return nil
}

func parseImageRef(ref string) (image, tag string) {
	if at := strings.LastIndex(ref, "@"); at > 0 {
		return ref[:at], ref[at+1:]
	}
	if colon := strings.LastIndex(ref, ":"); colon > 0 {
		after := ref[colon+1:]
		if !strings.Contains(after, "/") {
			return ref[:colon], after
		}
	}
	return ref, ""
}

func assessDep(e depEntry) (string, string) {
	if e.HasNoTag {
		return "high", "No tag specified; defaults to :latest which is mutable"
	}
	if e.IsLatest {
		return "high", "Using :latest tag; pin to a specific version or digest"
	}
	if e.IsDigest {
		return "low", "Pinned to digest; fully reproducible"
	}
	if isSemverTag(e.Tag) {
		return "low", "Pinned to specific version"
	}
	return "medium", "Tag may be mutable; consider pinning to a semver tag or digest"
}

func isSemverTag(tag string) bool {
	if tag == "" {
		return false
	}
	tag = strings.TrimPrefix(tag, "v")
	parts := strings.Split(tag, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func printDeps(r depsResult) {
	fmt.Printf("Dependency Audit (%d images, %d risky, %d pinned)\n\n", r.Total, r.Risky, r.Pinned)
	for _, e := range r.Entries {
		tag := e.Tag
		if tag == "" {
			tag = "(none)"
		}
		fmt.Printf("  %-30s %-15s [%s]\n", e.Image, tag, e.RiskLevel)
		fmt.Printf("    service: %s  file: %s\n", e.Service, e.File)
		fmt.Printf("    %s\n\n", e.Advice)
	}
}
