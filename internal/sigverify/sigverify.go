package sigverify

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
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices       int `json:"total_services"`
	TotalFindings       int `json:"total_findings"`
	UnsignedImage       int `json:"unsigned_image"`
	NoContentTrust      int `json:"no_content_trust"`
	NoDigestPin         int `json:"no_digest_pin"`
	InsecureRegistry    int `json:"insecure_registry"`
	MissingVerifyPolicy int `json:"missing_verify_policy"`
}

var trustedRegistries = []string{
	"docker.io/", "ghcr.io/", "gcr.io/", "quay.io/",
	"public.ecr.aws/", "registry.k8s.io/", "mcr.microsoft.com/",
}

var insecureRegistryEnvKeys = []string{
	"insecure_registry", "insecure-registry",
	"registry_insecure", "skip_tls_verify",
	"tls_verify=false", "ssl_verify=false",
}

var cosignEnvKeys = []string{
	"cosign_experimental", "cosign_key", "cosign_public_key",
	"notary_url", "docker_content_trust",
	"sigstore_", "rekor_url",
}

func isDigestPinned(image string) bool {
	return strings.Contains(image, "@sha256:")
}

func isLatestOrUntagged(image string) bool {
	if image == "" {
		return false
	}
	if !strings.Contains(image, ":") {
		return true
	}
	parts := strings.SplitN(image, ":", 2)
	return len(parts) == 2 && (parts[1] == "latest" || parts[1] == "")
}

func hasContentTrustEnabled(env []string) bool {
	for _, e := range env {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "docker_content_trust=1") ||
			strings.Contains(lower, "docker_content_trust=true") {
			return true
		}
	}
	return false
}

func hasCosignVerification(env []string) bool {
	for _, e := range env {
		lower := strings.ToLower(e)
		for _, k := range cosignEnvKeys {
			if strings.Contains(lower, k) {
				return true
			}
		}
	}
	return false
}

func hasInsecureRegistrySetting(env []string) bool {
	for _, e := range env {
		lower := strings.ToLower(e)
		for _, k := range insecureRegistryEnvKeys {
			if strings.Contains(lower, k) {
				return true
			}
		}
	}
	return false
}

func isFromTrustedRegistry(image string) bool {
	lower := strings.ToLower(image)
	for _, r := range trustedRegistries {
		if strings.HasPrefix(lower, r) {
			return true
		}
	}
	if !strings.Contains(lower, "/") || !strings.Contains(lower, ".") {
		return true
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if svc.Image != "" && !isDigestPinned(svc.Image) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "no_digest_pin",
			Message: fmt.Sprintf("Service '%s' image '%s' is not pinned by digest (@sha256:); image content may change between pulls without detection", svc.Name, svc.Image),
		})
	}

	if svc.Image != "" && isLatestOrUntagged(svc.Image) && !isDigestPinned(svc.Image) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "unsigned_image",
			Message: fmt.Sprintf("Service '%s' uses '%s' without a specific tag or digest; this image version is unverifiable and may be tampered with", svc.Name, svc.Image),
		})
	}

	if !hasContentTrustEnabled(svc.Environment) && !hasCosignVerification(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "no_content_trust",
			Message: fmt.Sprintf("Service '%s' has no DOCKER_CONTENT_TRUST or cosign verification configured; image signatures are not being validated", svc.Name),
		})
	}

	if hasInsecureRegistrySetting(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "insecure_registry",
			Message: fmt.Sprintf("Service '%s' has insecure registry or TLS verification disabled; images may be pulled without authenticity checks", svc.Name),
		})
	}

	if svc.Image != "" && !isFromTrustedRegistry(svc.Image) && !isDigestPinned(svc.Image) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "missing_verify_policy",
			Message: fmt.Sprintf("Service '%s' pulls from untrusted registry '%s' without digest pinning; consider enabling signature verification", svc.Name, svc.Image),
		})
	}

	return sr
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

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "unsigned_image":
				s.UnsignedImage++
			case "no_content_trust":
				s.NoContentTrust++
			case "no_digest_pin":
				s.NoDigestPin++
			case "insecure_registry":
				s.InsecureRegistry++
			case "missing_verify_policy":
				s.MissingVerifyPolicy++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Image Signature Verification Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Unsigned/untagged images:       %d\n", r.Summary.UnsignedImage)
	fmt.Fprintf(&b, "  No content trust:               %d\n", r.Summary.NoContentTrust)
	fmt.Fprintf(&b, "  Missing digest pin:             %d\n", r.Summary.NoDigestPin)
	fmt.Fprintf(&b, "  Insecure registry:              %d\n", r.Summary.InsecureRegistry)
	fmt.Fprintf(&b, "  Missing verify policy:          %d\n\n", r.Summary.MissingVerifyPolicy)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s\n", sr.Service)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		if len(sr.Findings) == 0 {
			fmt.Fprintf(&b, "    (no findings)\n")
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
