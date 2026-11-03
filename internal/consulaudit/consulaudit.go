package consulaudit

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
	NoACL          int `json:"no_acl"`
	NoTLS          int `json:"no_tls"`
	ExposedPort    int `json:"exposed_port"`
	DefaultToken   int `json:"default_token"`
	NoEncryptGossip int `json:"no_encrypt_gossip"`
	DevMode        int `json:"dev_mode"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func isConsulImage(image string) bool {
	lower := strings.ToLower(image)
	parts := []string{
		"consul", "hashicorp/consul", "library/consul",
		"bitnami/consul", "consul-enterprise",
	}
	for _, p := range parts {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func hasACL(envs []string, args []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "CONSUL_HTTP_TOKEN") ||
			strings.Contains(upper, "ACL_ENABLED=TRUE") ||
			strings.Contains(upper, "ACL_DEFAULT_POLICY") {
			return true
		}
	}
	for _, a := range args {
		if strings.Contains(a, "-acl-enabled") || strings.Contains(a, "acl.enabled=true") {
			return true
		}
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "CONSUL_CACERT") ||
			strings.Contains(upper, "CONSUL_CLIENT_CERT") ||
			strings.Contains(upper, "TLS_CERT_FILE") ||
			strings.Contains(upper, "CONSUL_TLS_ENABLE=TRUE") {
			return true
		}
	}
	return false
}

func hasGossipEncryption(envs []string, args []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "CONSUL_ENCRYPT") || strings.Contains(upper, "GOSSIP_ENCRYPTION_KEY") {
			return true
		}
	}
	for _, a := range args {
		if strings.Contains(a, "-encrypt") {
			return true
		}
	}
	return false
}

func hasDefaultToken(envs []string) bool {
	defaults := []string{"anonymous", "master", "default", "root", "changeme"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "consul_http_token=") || strings.Contains(lower, "acl_master_token=") {
			for _, d := range defaults {
				if strings.Contains(lower, "="+d) {
					return true
				}
			}
		}
	}
	return false
}

func isDevMode(envs []string, args []string) bool {
	for _, a := range args {
		if a == "-dev" || a == "--dev" {
			return true
		}
	}
	for _, e := range envs {
		if strings.Contains(strings.ToUpper(e), "CONSUL_DEV=TRUE") ||
			strings.Contains(strings.ToUpper(e), "CONSUL_LOCAL_CONFIG") && strings.Contains(strings.ToLower(e), "dev") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment
	args := svc.Command

	if !hasACL(envs, args) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "consul_no_acl",
			Message: fmt.Sprintf("service %q: Consul has no ACL enabled — any client can read/write the KV store", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "consul_no_tls",
			Message: fmt.Sprintf("service %q: Consul running without TLS — API and gossip traffic is plaintext", svc.Name),
		})
	}

	if !hasGossipEncryption(envs, args) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "consul_no_gossip_encrypt",
			Message: fmt.Sprintf("service %q: Consul gossip protocol is not encrypted", svc.Name),
		})
	}

	for _, pm := range svc.Ports {
		port := pm.TargetPort
		if port == 8500 || port == 8501 || port == 8600 || port == 8300 || port == 8301 || port == 8302 {
			if pm.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "consul_exposed_port",
					Message: fmt.Sprintf("service %q: Consul port %d exposed on all interfaces", svc.Name, port),
				})
			}
		}
	}

	if hasDefaultToken(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "consul_default_token",
			Message: fmt.Sprintf("service %q: Consul using default/weak ACL token", svc.Name),
		})
	}

	if isDevMode(envs, args) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "consul_dev_mode",
			Message: fmt.Sprintf("service %q: Consul running in development mode — all security is disabled", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isConsulImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "consul_no_acl":
					r.Summary.NoACL++
				case "consul_no_tls":
					r.Summary.NoTLS++
				case "consul_exposed_port":
					r.Summary.ExposedPort++
				case "consul_default_token":
					r.Summary.DefaultToken++
				case "consul_no_gossip_encrypt":
					r.Summary.NoEncryptGossip++
				case "consul_dev_mode":
					r.Summary.DevMode++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Consul Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No Consul services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_acl=%d no_tls=%d exposed_port=%d default_token=%d no_gossip_encrypt=%d dev_mode=%d\n",
		r.Summary.NoACL, r.Summary.NoTLS, r.Summary.ExposedPort,
		r.Summary.DefaultToken, r.Summary.NoEncryptGossip, r.Summary.DevMode)

	return b.String()
}
