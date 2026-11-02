package imagepin

import (
	"fmt"
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
	Image    string    `json:"image"`
	Tag      string    `json:"tag"`
	Digest   string    `json:"digest"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices int `json:"total_services"`
	NoTag         int `json:"no_tag"`
	LatestTag     int `json:"latest_tag"`
	MutableTag    int `json:"mutable_tag"`
	NoDigest      int `json:"no_digest"`
	TotalFindings int `json:"total_findings"`
}

var mutableTagPrefixes = []string{
	"latest", "stable", "edge", "nightly", "dev", "beta", "alpha",
	"master", "main", "canary", "rc",
}

func isMutableTag(tag string) bool {
	lower := strings.ToLower(tag)
	for _, prefix := range mutableTagPrefixes {
		if lower == prefix || strings.HasPrefix(lower, prefix+"-") || strings.HasPrefix(lower, prefix+".") {
			return true
		}
	}
	return false
}

func parseImageRef(image string) (name, tag, digest string) {
	if idx := strings.Index(image, "@sha256:"); idx >= 0 {
		digest = image[idx+1:]
		image = image[:idx]
	}
	if idx := strings.LastIndex(image, ":"); idx >= 0 && !strings.Contains(image[idx:], "/") {
		tag = image[idx+1:]
		name = image[:idx]
	} else {
		name = image
	}
	return
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
	name, tag, digest := parseImageRef(svc.Image)
	sr := ServiceResult{
		Service: svc.Name,
		File:    file,
		Image:   svc.Image,
		Tag:     tag,
		Digest:  digest,
	}

	if svc.Image == "" || strings.HasPrefix(svc.Image, "${") {
		return sr
	}

	_ = name

	if tag == "" && digest == "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "image_pin_no_tag",
			Message: fmt.Sprintf("Service '%s' uses image '%s' with no tag or digest; builds are not reproducible", svc.Name, svc.Image),
		})
	} else if tag == "latest" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "image_pin_latest",
			Message: fmt.Sprintf("Service '%s' uses ':latest' tag; pin to a specific version for reproducible builds", svc.Name),
		})
	} else if isMutableTag(tag) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "image_pin_mutable",
			Message: fmt.Sprintf("Service '%s' uses mutable tag ':%s'; consider pinning to an immutable version or digest", svc.Name, tag),
		})
	}

	if digest == "" && tag != "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "info",
			Rule:    "image_pin_no_digest",
			Message: fmt.Sprintf("Service '%s' has no digest pin; add @sha256:... for supply-chain integrity", svc.Name),
		})
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "image_pin_no_tag":
				s.NoTag++
			case "image_pin_latest":
				s.LatestTag++
			case "image_pin_mutable":
				s.MutableTag++
			case "image_pin_no_digest":
				s.NoDigest++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Image Pinning Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No tag:       %d\n", r.Summary.NoTag)
	fmt.Fprintf(&b, "  Latest tag:   %d\n", r.Summary.LatestTag)
	fmt.Fprintf(&b, "  Mutable tag:  %d\n", r.Summary.MutableTag)
	fmt.Fprintf(&b, "  No digest:    %d\n\n", r.Summary.NoDigest)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s image: %s\n", sr.Service, sr.Image)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
