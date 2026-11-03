package imagetrust

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type TrustLevel string

const (
	TrustPinned     TrustLevel = "pinned"
	TrustTagged     TrustLevel = "tagged"
	TrustLatest     TrustLevel = "latest"
	TrustUnspecified TrustLevel = "unspecified"
)

type Finding struct {
	Service     string `json:"service"`
	Source      string `json:"source"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
	Line        int    `json:"line,omitempty"`
	Remediation string `json:"remediation"`
}

type ServiceResult struct {
	Service    string     `json:"service"`
	Source     string     `json:"source"`
	Image      string     `json:"image"`
	Registry   string     `json:"registry"`
	Tag        string     `json:"tag"`
	HasDigest  bool       `json:"has_digest"`
	TrustLevel TrustLevel `json:"trust_level"`
	Findings   []Finding  `json:"findings,omitempty"`
}

type Summary struct {
	TotalServices  int `json:"total_services"`
	PinnedCount    int `json:"pinned_count"`
	LatestCount    int `json:"latest_count"`
	UntaggedCount  int `json:"untagged_count"`
	UnofficialCount int `json:"unofficial_count"`
	TotalFindings  int `json:"total_findings"`
}

type Report struct {
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var officialRegistries = []string{
	"docker.io",
	"ghcr.io",
	"gcr.io",
	"registry.k8s.io",
	"quay.io",
	"mcr.microsoft.com",
	"public.ecr.aws",
	"nvcr.io",
}

func parseImage(image string) (registry, repo, tag string, hasDigest bool) {
	if image == "" {
		return "", "", "", false
	}

	ref := image
	if idx := strings.Index(ref, "@sha256:"); idx >= 0 {
		hasDigest = true
		ref = ref[:idx]
	}

	if idx := strings.LastIndex(ref, ":"); idx >= 0 {
		candidate := ref[idx+1:]
		if !strings.Contains(candidate, "/") {
			tag = candidate
			ref = ref[:idx]
		}
	}

	parts := strings.SplitN(ref, "/", 3)
	switch {
	case len(parts) == 1:
		registry = "docker.io"
		repo = "library/" + parts[0]
	case len(parts) == 2:
		if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
			registry = parts[0]
			repo = parts[1]
		} else {
			registry = "docker.io"
			repo = ref
		}
	default:
		registry = parts[0]
		repo = parts[1] + "/" + parts[2]
	}

	if tag == "" && !hasDigest {
		tag = "latest"
	}

	return registry, repo, tag, hasDigest
}

func isOfficialRegistry(registry string) bool {
	lower := strings.ToLower(registry)
	for _, r := range officialRegistries {
		if lower == r {
			return true
		}
	}
	if strings.HasSuffix(lower, ".amazonaws.com") {
		return true
	}
	return false
}

func Analyze(collected *collect.Collected) Report {
	var services []ServiceResult
	var s Summary

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(cf.Path, svc)
			s.TotalServices++
			if sr.HasDigest {
				s.PinnedCount++
			}
			if sr.TrustLevel == TrustLatest {
				s.LatestCount++
			}
			if sr.TrustLevel == TrustUnspecified {
				s.UntaggedCount++
			}
			if sr.Registry != "" && !isOfficialRegistry(sr.Registry) {
				s.UnofficialCount++
			}
			s.TotalFindings += len(sr.Findings)
			services = append(services, sr)
		}
	}

	return Report{Services: services, Summary: s}
}

func analyzeService(path string, svc compose.Service) ServiceResult {
	registry, _, tag, hasDigest := parseImage(svc.Image)

	trust := TrustTagged
	switch {
	case hasDigest:
		trust = TrustPinned
	case svc.Image == "":
		trust = TrustUnspecified
	case tag == "latest":
		trust = TrustLatest
	}

	sr := ServiceResult{
		Service:    svc.Name,
		Source:     path,
		Image:      svc.Image,
		Registry:   registry,
		Tag:        tag,
		HasDigest:  hasDigest,
		TrustLevel: trust,
	}

	if svc.Image == "" {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			Source:      path,
			RuleID:      "no_image_specified",
			Severity:    "medium",
			Detail:      "service has no image reference; build-only services should still declare an image for provenance tracking",
			Line:        svc.ImageLine,
			Remediation: "Add an explicit image: field with a tagged or digest-pinned reference",
		})
		return sr
	}

	if tag == "latest" && !hasDigest {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			Source:      path,
			RuleID:      "mutable_latest_tag",
			Severity:    "high",
			Detail:      fmt.Sprintf("image %q uses the mutable :latest tag; builds are not reproducible", svc.Image),
			Line:        svc.ImageLine,
			Remediation: "Pin to a specific version tag (e.g. :3.2.1) or use a sha256 digest",
		})
	}

	if !hasDigest {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			Source:      path,
			RuleID:      "no_digest_pin",
			Severity:    "low",
			Detail:      fmt.Sprintf("image %q is not pinned by digest; tag contents can change", svc.Image),
			Line:        svc.ImageLine,
			Remediation: "Pin with a sha256 digest (e.g. image@sha256:abc123...)",
		})
	}

	if registry != "" && !isOfficialRegistry(registry) {
		sr.Findings = append(sr.Findings, Finding{
			Service:     svc.Name,
			Source:      path,
			RuleID:      "unofficial_registry",
			Severity:    "medium",
			Detail:      fmt.Sprintf("image pulled from unofficial registry %q; verify trust chain", registry),
			Line:        svc.ImageLine,
			Remediation: "Use images from official registries (Docker Hub, GHCR, GCR, Quay) or document the trust basis for custom registries",
		})
	}

	return sr
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Container Image Trust Analysis\n")
	b.WriteString(strings.Repeat("=", 62) + "\n\n")

	fmt.Fprintf(&b, "  Services analyzed:  %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Digest-pinned:      %d\n", r.Summary.PinnedCount)
	fmt.Fprintf(&b, "  Using :latest:      %d\n", r.Summary.LatestCount)
	fmt.Fprintf(&b, "  No image:           %d\n", r.Summary.UntaggedCount)
	fmt.Fprintf(&b, "  Unofficial registry: %d\n", r.Summary.UnofficialCount)
	fmt.Fprintf(&b, "  Total findings:     %d\n\n", r.Summary.TotalFindings)

	fmt.Fprintf(&b, "  %-16s %-30s %-10s\n", "Service", "Image", "Trust")
	b.WriteString("  " + strings.Repeat("-", 56) + "\n")
	for _, sr := range r.Services {
		img := sr.Image
		if len(img) > 30 {
			img = img[:27] + "..."
		}
		if img == "" {
			img = "(none)"
		}
		fmt.Fprintf(&b, "  %-16s %-30s %-10s\n", truncate(sr.Service, 16), img, sr.TrustLevel)
	}
	b.WriteString("\n")

	hasFindings := false
	for _, sr := range r.Services {
		if len(sr.Findings) > 0 {
			hasFindings = true
			break
		}
	}

	if hasFindings {
		b.WriteString("  Findings:\n")
		b.WriteString("  " + strings.Repeat("-", 56) + "\n")
		for _, sr := range r.Services {
			for _, f := range sr.Findings {
				sev := strings.ToUpper(f.Severity)
				if f.Line > 0 {
					fmt.Fprintf(&b, "  [%s] %s line %d: %s (%s)\n", sev, f.Service, f.Line, f.Detail, f.RuleID)
				} else {
					fmt.Fprintf(&b, "  [%s] %s: %s (%s)\n", sev, f.Service, f.Detail, f.RuleID)
				}
			}
		}
		b.WriteString("\n")
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
