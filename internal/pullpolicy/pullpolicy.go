package pullpolicy

import (
	"fmt"
	"math"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type Finding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Service     string `json:"service"`
	Image       string `json:"image"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

type Report struct {
	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
}

type Summary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByRule     map[string]int `json:"by_rule"`
	Services   int            `json:"services_affected"`
}

func Analyze(c *collect.Collected) Report {
	var findings []Finding

	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if svc.Image == "" {
				continue
			}
			findings = append(findings, checkImage(svc.Name, svc.Image)...)
		}
	}

	r := Report{Findings: findings}
	r.Summary = buildSummary(findings)
	return r
}

func checkImage(service, image string) []Finding {
	var findings []Finding

	ref := parseImageRef(image)

	if ref.Tag == "latest" {
		findings = append(findings, Finding{
			RuleID:      "pullpolicy_latest_tag",
			Severity:    "high",
			Service:     service,
			Image:       image,
			Description: "Image explicitly uses :latest tag; deployments are non-reproducible",
			Remediation: "Pin image to a specific version tag (e.g. nginx:1.25.3) or digest",
		})
	} else if ref.Tag == "" && ref.Digest == "" {
		findings = append(findings, Finding{
			RuleID:      "pullpolicy_no_tag",
			Severity:    "high",
			Service:     service,
			Image:       image,
			Description: "Image has no tag; Docker defaults to :latest making builds non-reproducible",
			Remediation: "Add an explicit version tag (e.g. myimage:1.0) or use a digest reference",
		})
	}

	if ref.Digest == "" && ref.Tag != "" && ref.Tag != "latest" {
		findings = append(findings, Finding{
			RuleID:      "pullpolicy_no_digest",
			Severity:    "medium",
			Service:     service,
			Image:       image,
			Description: "Image uses a mutable tag without digest pinning; tag could be overwritten",
			Remediation: "Pin image with digest (e.g. nginx@sha256:abc123...) for supply-chain integrity",
		})
	}

	if isVariableRef(image) {
		findings = append(findings, Finding{
			RuleID:      "pullpolicy_variable_image",
			Severity:    "medium",
			Service:     service,
			Image:       image,
			Description: "Image reference contains variable substitution; version not statically verifiable",
			Remediation: "Document expected image versions; consider pinning in .env with digest references",
		})
	}

	return findings
}

type imageRef struct {
	Registry string
	Name     string
	Tag      string
	Digest   string
}

func parseImageRef(image string) imageRef {
	var ref imageRef

	if idx := strings.Index(image, "@sha256:"); idx != -1 {
		ref.Digest = image[idx+1:]
		image = image[:idx]
	}

	if idx := strings.LastIndex(image, ":"); idx != -1 {
		candidate := image[idx+1:]
		if !strings.Contains(candidate, "/") {
			ref.Tag = candidate
			image = image[:idx]
		}
	}

	parts := strings.Split(image, "/")
	if len(parts) >= 2 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		ref.Registry = parts[0]
		ref.Name = strings.Join(parts[1:], "/")
	} else {
		ref.Name = image
	}

	return ref
}

func isVariableRef(image string) bool {
	return strings.Contains(image, "${") || strings.Contains(image, "$")
}

func buildSummary(findings []Finding) Summary {
	s := Summary{
		Total:      len(findings),
		BySeverity: map[string]int{},
		ByRule:     map[string]int{},
	}
	services := map[string]bool{}
	for _, f := range findings {
		s.BySeverity[f.Severity]++
		s.ByRule[f.RuleID]++
		services[f.Service] = true
	}
	s.Services = len(services)
	return s
}

func Score(r Report) float64 {
	if r.Summary.Total == 0 {
		return 100
	}
	penalty := 0.0
	for _, f := range r.Findings {
		switch f.Severity {
		case "high":
			penalty += 25
		case "medium":
			penalty += 10
		}
	}
	return math.Max(0, 100-penalty)
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Image Pull Policy Audit (%d findings)\n\n", r.Summary.Total)
	if r.Summary.Total == 0 {
		b.WriteString("  No image pull policy issues detected.\n")
		return b.String()
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  [%s] %s  service=%s  image=%s\n", f.Severity, f.RuleID, f.Service, f.Image)
		fmt.Fprintf(&b, "    %s\n", f.Description)
		fmt.Fprintf(&b, "    fix: %s\n\n", f.Remediation)
	}
	fmt.Fprintf(&b, "  Score: %.0f/100  (%d services affected)\n", Score(r), r.Summary.Services)
	return b.String()
}
