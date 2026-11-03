package registry

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	File        string `json:"file"`
	Image       string `json:"image"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type ImageResult struct {
	Image    string `json:"image"`
	Registry string `json:"registry"`
	Tag      string `json:"tag"`
	Digest   string `json:"digest"`
	Trusted  bool   `json:"trusted"`
}

type Summary struct {
	TotalImages    int `json:"total_images"`
	LatestTags     int `json:"latest_tags"`
	UnpinnedImages int `json:"unpinned_images"`
	UntrustedRegs  int `json:"untrusted_registries"`
	TotalFindings  int `json:"total_findings"`
	Score          int `json:"score"`
}

type Report struct {
	Images   []ImageResult `json:"images"`
	Findings []Finding     `json:"findings"`
	Summary  Summary       `json:"summary"`
}

var trustedRegistries = map[string]bool{
	"docker.io":                   true,
	"gcr.io":                      true,
	"ghcr.io":                     true,
	"quay.io":                     true,
	"registry.k8s.io":             true,
	"mcr.microsoft.com":           true,
	"public.ecr.aws":              true,
	"nvcr.io":                     true,
	"registry.access.redhat.com":  true,
}

func Analyze(collected *collect.Collected) Report {
	var images []ImageResult
	var findings []Finding

	for _, df := range collected.Dockerfiles {
		for _, baseImage := range extractBaseImages(df.Content) {
			img := ParseImage(baseImage)
			img.Trusted = IsTrusted(img.Registry)
			images = append(images, img)
			findings = append(findings, checkImage(df.Path, baseImage, img)...)
		}
	}

	for _, cf := range collected.ComposeFiles {
		analyzeComposeServices(cf, &images, &findings)
	}

	score := 100
	latestCount, unpinnedCount, untrustedCount := 0, 0, 0
	for _, img := range images {
		if img.Tag == "latest" || img.Tag == "" {
			latestCount++
		}
		if img.Digest == "" {
			unpinnedCount++
		}
		if !img.Trusted {
			untrustedCount++
		}
	}
	if len(images) > 0 {
		score -= latestCount * 15
		score -= unpinnedCount * 10
		score -= untrustedCount * 20
		if score < 0 {
			score = 0
		}
	}

	return Report{
		Images:   images,
		Findings: findings,
		Summary: Summary{
			TotalImages:    len(images),
			LatestTags:     latestCount,
			UnpinnedImages: unpinnedCount,
			UntrustedRegs:  untrustedCount,
			TotalFindings:  len(findings),
			Score:          score,
		},
	}
}

func extractBaseImages(content string) []string {
	var images []string
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if !strings.HasPrefix(upper, "FROM ") {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) >= 2 {
			images = append(images, parts[1])
		}
	}
	return images
}

func analyzeComposeServices(cf compose.File, images *[]ImageResult, findings *[]Finding) {
	for _, svc := range cf.Services {
		if svc.Image == "" {
			continue
		}
		img := ParseImage(svc.Image)
		img.Trusted = IsTrusted(img.Registry)
		*images = append(*images, img)

		fs := checkImage(cf.Path, svc.Image, img)
		for i := range fs {
			fs[i].Detail = fmt.Sprintf("service %q: %s", svc.Name, fs[i].Detail)
		}
		*findings = append(*findings, fs...)
	}
}

func ParseImage(ref string) ImageResult {
	r := ImageResult{Image: ref}

	if at := strings.Index(ref, "@"); at >= 0 {
		r.Digest = ref[at+1:]
		ref = ref[:at]
	}

	parts := strings.SplitN(ref, "/", 3)
	switch {
	case len(parts) == 3:
		r.Registry = parts[0]
		ref = parts[1] + "/" + parts[2]
	case len(parts) == 2 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")):
		r.Registry = parts[0]
		ref = parts[1]
	default:
		r.Registry = "docker.io"
	}

	if colon := strings.LastIndex(ref, ":"); colon >= 0 {
		r.Tag = ref[colon+1:]
	}

	return r
}

func IsTrusted(reg string) bool {
	reg = strings.Split(reg, ":")[0]
	return trustedRegistries[reg]
}

func checkImage(file, rawImage string, img ImageResult) []Finding {
	var fs []Finding

	if img.Tag == "latest" || img.Tag == "" {
		tagLabel := img.Tag
		if tagLabel == "" {
			tagLabel = "(implicit latest)"
		}
		fs = append(fs, Finding{
			File:        file,
			Image:       rawImage,
			RuleID:      "registry_latest_tag",
			Severity:    "high",
			Detail:      fmt.Sprintf("image %q uses tag %q — pin a specific version", rawImage, tagLabel),
			Remediation: "Pin image to a specific version tag (e.g. :1.25.3) or digest",
		})
	}

	if img.Digest == "" {
		fs = append(fs, Finding{
			File:        file,
			Image:       rawImage,
			RuleID:      "registry_no_digest",
			Severity:    "medium",
			Detail:      fmt.Sprintf("image %q has no digest pin — vulnerable to tag mutation", rawImage),
			Remediation: "Pin image by digest (e.g. image@sha256:abc123...)",
		})
	}

	if !img.Trusted {
		fs = append(fs, Finding{
			File:        file,
			Image:       rawImage,
			RuleID:      "registry_untrusted",
			Severity:    "high",
			Detail:      fmt.Sprintf("image %q from untrusted registry %q", rawImage, img.Registry),
			Remediation: "Use images from trusted registries or add registry to trusted list",
		})
	}

	return fs
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Container Registry Security Audit\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	fmt.Fprintf(&sb, "  Images Scanned:       %d\n", r.Summary.TotalImages)
	fmt.Fprintf(&sb, "  Latest Tags:          %d\n", r.Summary.LatestTags)
	fmt.Fprintf(&sb, "  Unpinned (no digest): %d\n", r.Summary.UnpinnedImages)
	fmt.Fprintf(&sb, "  Untrusted Registries: %d\n", r.Summary.UntrustedRegs)
	fmt.Fprintf(&sb, "  Registry Score:       %d/100\n\n", r.Summary.Score)

	if len(r.Findings) > 0 {
		sb.WriteString("Findings:\n")
		for i, f := range r.Findings {
			fmt.Fprintf(&sb, "  %d. [%s] %s (%s)\n", i+1, f.Severity, f.Detail, f.RuleID)
			fmt.Fprintf(&sb, "     Fix: %s\n", f.Remediation)
		}
		sb.WriteString("\n")
	}

	if len(r.Images) > 0 {
		sb.WriteString("Images:\n")
		for _, img := range r.Images {
			trusted := "trusted"
			if !img.Trusted {
				trusted = "UNTRUSTED"
			}
			fmt.Fprintf(&sb, "  - %s (registry=%s, tag=%s, %s)\n", img.Image, img.Registry, img.Tag, trusted)
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
