package vaultaudit

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
	Findings []Finding `json:"findings"`
}

type Summary struct {
	DevMode         int `json:"dev_mode"`
	NoTLS           int `json:"no_tls"`
	ExposedPort     int `json:"exposed_port"`
	RootTokenInEnv  int `json:"root_token_in_env"`
	DefaultPassword int `json:"default_password"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var vaultImages = []string{
	"vault", "hashicorp/vault",
}

func isVaultImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range vaultImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func isDevMode(envs []string, command []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "vault_dev_root_token_id") ||
			strings.Contains(lower, "vault_dev_listen_address") {
			return true
		}
	}
	for _, c := range command {
		if c == "server" {
			continue
		}
		if c == "-dev" || c == "--dev" || strings.HasPrefix(c, "-dev-") {
			return true
		}
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "VAULT_ADDR") && strings.Contains(upper, "HTTPS") {
			return true
		}
		if strings.Contains(upper, "VAULT_TLS_CERT_FILE") ||
			strings.Contains(upper, "VAULT_TLS_KEY_FILE") ||
			strings.Contains(upper, "VAULT_CACERT") {
			return true
		}
	}
	return false
}

func hasRootTokenInEnv(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "vault_token=") ||
			strings.Contains(lower, "vault_dev_root_token_id=") {
			return true
		}
	}
	return false
}

func hasDefaultPassword(envs []string) bool {
	defaults := []string{"root", "admin", "password", "changeme", "vault", "default", "test", "myroot"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "vault_dev_root_token_id=") || strings.Contains(lower, "vault_token=") {
			for _, d := range defaults {
				if strings.HasSuffix(lower, "="+d) {
					return true
				}
			}
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	if isDevMode(envs, svc.Command) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "vault_dev_mode",
			Message: fmt.Sprintf("service %q: Vault running in dev mode — all data is in-memory and unsealed", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "vault_no_tls",
			Message: fmt.Sprintf("service %q: Vault running without TLS encryption", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		8200: "Vault API/UI",
		8201: "Vault cluster (replication)",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "vault_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasRootTokenInEnv(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "vault_root_token_in_env",
			Message: fmt.Sprintf("service %q: Vault root token exposed in environment variable", svc.Name),
		})
	}

	if hasDefaultPassword(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "vault_default_password",
			Message: fmt.Sprintf("service %q: Vault using default/weak root token", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isVaultImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "vault_dev_mode":
					r.Summary.DevMode++
				case "vault_no_tls":
					r.Summary.NoTLS++
				case "vault_exposed_port":
					r.Summary.ExposedPort++
				case "vault_root_token_in_env":
					r.Summary.RootTokenInEnv++
				case "vault_default_password":
					r.Summary.DefaultPassword++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Vault Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No Vault services found.\n")
		return b.String()
	}

	for _, svc := range r.Services {
		fmt.Fprintf(&b, "  Service: %s\n", svc.Service)
		if len(svc.Findings) == 0 {
			b.WriteString("    No findings.\n")
		}
		for _, f := range svc.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Level, f.Rule, f.Message)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "  Summary: dev_mode=%d no_tls=%d exposed_port=%d root_token_in_env=%d default_password=%d\n",
		r.Summary.DevMode, r.Summary.NoTLS, r.Summary.ExposedPort,
		r.Summary.RootTokenInEnv, r.Summary.DefaultPassword)

	return b.String()
}
