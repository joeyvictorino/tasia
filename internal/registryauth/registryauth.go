package registryauth

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
	TotalServices        int `json:"total_services"`
	TotalFindings        int `json:"total_findings"`
	InsecureRegistries   int `json:"insecure_registries"`
	PlaintextCredentials int `json:"plaintext_credentials"`
	UnpinnedImages       int `json:"unpinned_images"`
	MissingAuth          int `json:"missing_auth"`
}

var knownPublicRegistries = map[string]bool{
	"docker.io":       true,
	"index.docker.io": true,
	"ghcr.io":         true,
	"gcr.io":          true,
	"quay.io":         true,
	"mcr.microsoft.com": true,
	"public.ecr.aws":  true,
	"registry.hub.docker.com": true,
	"nvcr.io":         true,
}

var registryCredEnvPatterns = []string{
	"REGISTRY_PASSWORD",
	"REGISTRY_TOKEN",
	"REGISTRY_AUTH",
	"DOCKER_PASSWORD",
	"DOCKER_TOKEN",
	"DOCKER_AUTH",
	"CR_PAT",
	"GITHUB_TOKEN",
	"GCR_KEY",
	"AWS_ACCESS_KEY",
}

func extractRegistry(image string) string {
	if image == "" {
		return ""
	}
	image = strings.TrimPrefix(image, "http://")
	image = strings.TrimPrefix(image, "https://")
	parts := strings.SplitN(image, "/", 2)
	if len(parts) < 2 {
		return ""
	}
	host := parts[0]
	if strings.Contains(host, ".") || strings.Contains(host, ":") {
		return host
	}
	return ""
}

func isHTTPRegistry(image string) bool {
	return strings.HasPrefix(image, "http://")
}

func isPublicRegistry(reg string) bool {
	host := strings.Split(reg, ":")[0]
	return knownPublicRegistries[host]
}

func hasDigestPin(image string) bool {
	return strings.Contains(image, "@sha256:")
}

func hasPlaintextCredInEnv(envVars []string) (string, string) {
	for _, e := range envVars {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToUpper(parts[0])
		val := parts[1]
		for _, pat := range registryCredEnvPatterns {
			if strings.Contains(key, pat) && val != "" && !strings.HasPrefix(val, "${") && !strings.HasPrefix(val, "$") {
				return parts[0], val
			}
		}
	}
	return "", ""
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
	sr := ServiceResult{Service: svc.Name, File: file}

	reg := extractRegistry(svc.Image)

	if isHTTPRegistry(svc.Image) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "registryauth_insecure_http",
			Message: fmt.Sprintf("Service '%s' pulls image from insecure HTTP registry '%s'; use HTTPS to prevent MITM attacks", svc.Name, svc.Image),
		})
	}

	if reg != "" && !isPublicRegistry(reg) && !hasDigestPin(svc.Image) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "registryauth_private_no_pin",
			Message: fmt.Sprintf("Service '%s' uses private registry '%s' without digest pinning; pin with @sha256: to ensure image integrity", svc.Name, reg),
		})
	}

	if reg != "" && strings.Contains(reg, "localhost") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "registryauth_localhost_registry",
			Message: fmt.Sprintf("Service '%s' pulls from localhost registry '%s'; localhost registries typically lack TLS and authentication", svc.Name, reg),
		})
	}

	if reg != "" && strings.Contains(reg, ":5000") {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "registryauth_default_port",
			Message: fmt.Sprintf("Service '%s' uses default registry port 5000 on '%s'; default-port registries often run without auth", svc.Name, reg),
		})
	}

	if key, _ := hasPlaintextCredInEnv(svc.Environment); key != "" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "registryauth_plaintext_cred",
			Message: fmt.Sprintf("Service '%s' has plaintext registry credential in environment variable '%s'; use secrets management instead", svc.Name, key),
		})
	}

	for _, e := range svc.Environment {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToUpper(parts[0])
		val := parts[1]
		if (key == "DOCKER_CONFIG" || key == "REGISTRY_CONFIG") && val != "" {
			if !strings.HasPrefix(val, "/run/secrets") && !strings.HasPrefix(val, "/etc/secrets") {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "medium",
					Rule:    "registryauth_config_exposure",
					Message: fmt.Sprintf("Service '%s' sets %s to '%s'; Docker config files may contain encoded credentials—mount from secrets", svc.Name, parts[0], val),
				})
			}
		}
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "registryauth_insecure_http":
				s.InsecureRegistries++
			case "registryauth_plaintext_cred":
				s.PlaintextCredentials++
			case "registryauth_private_no_pin":
				s.UnpinnedImages++
			case "registryauth_localhost_registry", "registryauth_default_port":
				s.MissingAuth++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Registry Authentication Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Insecure registries:    %d\n", r.Summary.InsecureRegistries)
	fmt.Fprintf(&b, "  Plaintext credentials:  %d\n", r.Summary.PlaintextCredentials)
	fmt.Fprintf(&b, "  Unpinned private imgs:  %d\n", r.Summary.UnpinnedImages)
	fmt.Fprintf(&b, "  Missing auth hints:     %d\n\n", r.Summary.MissingAuth)
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
