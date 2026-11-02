package layertrust

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

type TrustLevel string

const (
	Trusted    TrustLevel = "trusted"
	Suspicious TrustLevel = "suspicious"
	Untrusted  TrustLevel = "untrusted"
)

type LayerFinding struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Instruction string `json:"instruction"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Trust       string `json:"trust"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
}

type DockerfileResult struct {
	File        string         `json:"file"`
	BaseImage   string         `json:"base_image"`
	BaseTrust   string         `json:"base_trust"`
	TotalLayers int            `json:"total_layers"`
	Findings    []LayerFinding `json:"findings,omitempty"`
}

type Summary struct {
	TotalDockerfiles int `json:"total_dockerfiles"`
	TotalLayers      int `json:"total_layers"`
	TotalFindings    int `json:"total_findings"`
	UntrustedBases   int `json:"untrusted_bases"`
	SuspiciousLayers int `json:"suspicious_layers"`
}

type Report struct {
	Dockerfiles []DockerfileResult `json:"dockerfiles"`
	Summary     Summary            `json:"summary"`
}

var trustedRegistries = map[string]bool{
	"docker.io":                true,
	"ghcr.io":                 true,
	"gcr.io":                  true,
	"registry.k8s.io":         true,
	"mcr.microsoft.com":       true,
	"public.ecr.aws":          true,
	"quay.io":                 true,
	"registry.access.redhat.com": true,
}

var secretPatterns = []string{
	".pem", ".key", ".p12", ".pfx", ".jks",
	"id_rsa", "id_ed25519", "id_ecdsa",
	".env", "credentials", "secret",
	"password", "token", "apikey",
}

var nonStandardRepos = []string{
	"ppa:", "deb http://", "deb https://",
	"rpm --import", "yum-config-manager --add-repo",
	"curl -fssl", "wget -qo-",
	"| sh", "| bash",
}

func Analyze(collected *collect.Collected) Report {
	var results []DockerfileResult

	for _, df := range collected.Dockerfiles {
		r := analyzeDockerfile(&df)
		results = append(results, r)
	}

	summary := Summary{TotalDockerfiles: len(results)}
	for _, r := range results {
		summary.TotalLayers += r.TotalLayers
		summary.TotalFindings += len(r.Findings)
		if r.BaseTrust == string(Untrusted) {
			summary.UntrustedBases++
		}
		for _, f := range r.Findings {
			if f.Trust == string(Suspicious) || f.Trust == string(Untrusted) {
				summary.SuspiciousLayers++
			}
		}
	}

	return Report{Dockerfiles: results, Summary: summary}
}

func analyzeDockerfile(df *collect.Dockerfile) DockerfileResult {
	lines := strings.Split(df.Content, "\n")
	result := DockerfileResult{
		File:        df.Path,
		TotalLayers: countLayers(lines),
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		lineNum := i + 1

		if strings.HasPrefix(upper, "FROM ") {
			checkFromLine(trimmed, lineNum, df.Path, &result)
		}

		if strings.HasPrefix(upper, "COPY ") || strings.HasPrefix(upper, "ADD ") {
			checkCopyAdd(trimmed, lineNum, df.Path, &result)
		}

		if strings.HasPrefix(upper, "RUN ") {
			checkRunLine(trimmed, lineNum, df.Path, &result)
		}

		if strings.HasPrefix(upper, "ENV ") {
			checkEnvLine(trimmed, lineNum, df.Path, &result)
		}
	}

	return result
}

func countLayers(lines []string) int {
	count := 0
	for _, line := range lines {
		upper := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(upper, "FROM ") ||
			strings.HasPrefix(upper, "RUN ") ||
			strings.HasPrefix(upper, "COPY ") ||
			strings.HasPrefix(upper, "ADD ") {
			count++
		}
	}
	return count
}

func checkFromLine(line string, lineNum int, file string, result *DockerfileResult) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	image := parts[1]
	result.BaseImage = image

	registry := extractRegistry(image)
	tag := extractTag(image)

	if image == "scratch" {
		result.BaseTrust = string(Trusted)
		return
	}

	if registry != "" && !trustedRegistries[registry] {
		result.BaseTrust = string(Untrusted)
		result.Findings = append(result.Findings, LayerFinding{
			File:        file,
			Line:        lineNum,
			Instruction: line,
			RuleID:      "layer_untrusted_registry",
			Severity:    "high",
			Trust:       string(Untrusted),
			Detail:      fmt.Sprintf("Base image from unknown registry %q", registry),
			Remediation: "Use images from trusted registries (Docker Hub, GHCR, GCR, Quay, ECR)",
		})
		return
	}

	if tag == "" || tag == "latest" {
		result.BaseTrust = string(Suspicious)
		result.Findings = append(result.Findings, LayerFinding{
			File:        file,
			Line:        lineNum,
			Instruction: line,
			RuleID:      "layer_unpinned_base",
			Severity:    "medium",
			Trust:       string(Suspicious),
			Detail:      fmt.Sprintf("Base image %q is not pinned to a specific version", image),
			Remediation: "Pin base image to a specific tag or digest (e.g. python:3.12-slim or image@sha256:...)",
		})
		return
	}

	result.BaseTrust = string(Trusted)
}

func checkCopyAdd(line string, lineNum int, file string, result *DockerfileResult) {
	lower := strings.ToLower(line)

	for _, pattern := range secretPatterns {
		if strings.Contains(lower, pattern) {
			result.Findings = append(result.Findings, LayerFinding{
				File:        file,
				Line:        lineNum,
				Instruction: line,
				RuleID:      "layer_secret_added",
				Severity:    "critical",
				Trust:       string(Untrusted),
				Detail:      fmt.Sprintf("Layer copies file matching secret pattern %q into image", pattern),
				Remediation: "Use multi-stage builds or --mount=type=secret to avoid baking secrets into image layers",
			})
			return
		}
	}

	upper := strings.ToUpper(line)
	if strings.HasPrefix(upper, "ADD ") && (strings.Contains(lower, "http://") || strings.Contains(lower, "https://")) {
		result.Findings = append(result.Findings, LayerFinding{
			File:        file,
			Line:        lineNum,
			Instruction: line,
			RuleID:      "layer_add_url",
			Severity:    "high",
			Trust:       string(Suspicious),
			Detail:      "ADD fetches remote content without integrity verification",
			Remediation: "Use COPY with pre-downloaded and checksum-verified files, or RUN with curl and hash verification",
		})
	}
}

func checkRunLine(line string, lineNum int, file string, result *DockerfileResult) {
	lower := strings.ToLower(line)

	for _, pattern := range nonStandardRepos {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			result.Findings = append(result.Findings, LayerFinding{
				File:        file,
				Line:        lineNum,
				Instruction: line,
				RuleID:      "layer_nonstandard_repo",
				Severity:    "medium",
				Trust:       string(Suspicious),
				Detail:      "Layer installs packages from a non-standard repository source",
				Remediation: "Use only official distribution repositories; if third-party repos are needed, verify GPG keys",
			})
			return
		}
	}

	if strings.Contains(lower, "chmod 777") || strings.Contains(lower, "chmod a+rwx") {
		result.Findings = append(result.Findings, LayerFinding{
			File:        file,
			Line:        lineNum,
			Instruction: line,
			RuleID:      "layer_wide_permissions",
			Severity:    "medium",
			Trust:       string(Suspicious),
			Detail:      "Layer sets world-writable permissions",
			Remediation: "Use restrictive permissions (e.g. chmod 755 for directories, chmod 644 for files)",
		})
	}

	if strings.Contains(lower, "--no-check-certificate") || strings.Contains(lower, "--insecure") || strings.Contains(lower, "-k ") {
		result.Findings = append(result.Findings, LayerFinding{
			File:        file,
			Line:        lineNum,
			Instruction: line,
			RuleID:      "layer_insecure_download",
			Severity:    "high",
			Trust:       string(Untrusted),
			Detail:      "Layer downloads content with TLS verification disabled",
			Remediation: "Remove --no-check-certificate/--insecure flags; ensure TLS certificate chains are valid",
		})
	}
}

func checkEnvLine(line string, lineNum int, file string, result *DockerfileResult) {
	lower := strings.ToLower(line)
	for _, pattern := range []string{"password", "secret", "token", "api_key", "apikey", "private_key"} {
		if strings.Contains(lower, pattern) && strings.Contains(line, "=") {
			result.Findings = append(result.Findings, LayerFinding{
				File:        file,
				Line:        lineNum,
				Instruction: line,
				RuleID:      "layer_env_secret",
				Severity:    "critical",
				Trust:       string(Untrusted),
				Detail:      fmt.Sprintf("ENV sets a value matching secret pattern %q; secrets in ENV are visible in image metadata", pattern),
				Remediation: "Use --mount=type=secret or runtime environment variables instead of baking secrets into ENV",
			})
			return
		}
	}
}

func extractRegistry(image string) string {
	if strings.Contains(image, "@") {
		image = strings.SplitN(image, "@", 2)[0]
	}
	if strings.Contains(image, ":") {
		image = strings.SplitN(image, ":", 2)[0]
	}
	parts := strings.SplitN(image, "/", 2)
	if len(parts) == 1 {
		return ""
	}
	if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
		return parts[0]
	}
	return ""
}

func extractTag(image string) string {
	if strings.Contains(image, "@") {
		return "pinned-digest"
	}
	parts := strings.SplitN(image, ":", 2)
	if len(parts) == 1 {
		return ""
	}
	return parts[1]
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Image Layer Trust Analysis (%d Dockerfiles, %d layers, %d findings)\n\n",
		r.Summary.TotalDockerfiles, r.Summary.TotalLayers, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Untrusted base images:  %d\n", r.Summary.UntrustedBases)
	fmt.Fprintf(&b, "  Suspicious layers:      %d\n\n", r.Summary.SuspiciousLayers)

	for _, df := range r.Dockerfiles {
		if len(df.Findings) == 0 && df.BaseTrust == string(Trusted) {
			continue
		}
		fmt.Fprintf(&b, "  %s\n", df.File)
		if df.BaseImage != "" {
			fmt.Fprintf(&b, "    Base: %s [%s]\n", df.BaseImage, df.BaseTrust)
		}
		for _, f := range df.Findings {
			fmt.Fprintf(&b, "    [%s] L%d %s: %s\n", f.Severity, f.Line, f.RuleID, f.Detail)
			fmt.Fprintf(&b, "           Fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}
	return b.String()
}
