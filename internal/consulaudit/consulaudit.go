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
	NoACL           int `json:"no_acl"`
	NoTLS           int `json:"no_tls"`
	ExposedPort     int `json:"exposed_port"`
	UIExposed       int `json:"ui_exposed"`
	NoGossipEncrypt int `json:"no_gossip_encrypt"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var consulImages = []string{
	"consul", "hashicorp/consul",
}

func isConsulImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range consulImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasACL(envs []string, cmds []string) bool {
	for _, cmd := range cmds {
		lower := strings.ToLower(cmd)
		if strings.Contains(lower, "-dev") {
			return false
		}
	}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "consul_local_config") {
			if strings.Contains(lower, "\"enabled\":true") || strings.Contains(lower, "\"enabled\": true") {
				return true
			}
		}
		if strings.Contains(lower, "consul_acl_enabled=true") ||
			strings.Contains(lower, "consul_acl_default_policy=deny") {
			return true
		}
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "CONSUL_HTTP_SSL=TRUE") ||
			strings.Contains(upper, "CONSUL_CACERT") ||
			strings.Contains(upper, "CONSUL_CLIENT_CERT") ||
			strings.Contains(upper, "CONSUL_TLS_SERVER_NAME") ||
			strings.Contains(upper, "CONSUL_HTTPS_PORT") {
			return true
		}
	}
	return false
}

func hasGossipEncryption(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "CONSUL_ENCRYPT=") ||
			strings.Contains(upper, "GOSSIP_ENCRYPTION_KEY") ||
			strings.Contains(upper, "CONSUL_GOSSIP_ENCRYPT") {
			return true
		}
	}
	return false
}

func hasUIFlag(cmds []string) bool {
	for _, cmd := range cmds {
		lower := strings.ToLower(cmd)
		if strings.Contains(lower, "-ui") {
			return true
		}
	}
	return false
}

func isDevMode(cmds []string) bool {
	for _, cmd := range cmds {
		lower := strings.ToLower(cmd)
		if strings.Contains(lower, "-dev") {
			return true
		}
	}
	return false
}

func hasUIExposed(envs []string, cmds []string, ports []compose.PortMapping) bool {
	if !hasUIFlag(cmds) && !isDevMode(cmds) {
		return false
	}
	for _, p := range ports {
		if p.TargetPort == 8500 && p.IsAllInterfaces() {
			if !hasACL(envs, cmds) {
				return true
			}
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment
	cmds := svc.Command

	if !hasACL(envs, cmds) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "consul_no_acl",
			Message: fmt.Sprintf("service %q: Consul ACL not enabled or running in dev mode", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "consul_no_tls",
			Message: fmt.Sprintf("service %q: Consul running without TLS encryption", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		8500: "HTTP API",
		8600: "DNS interface",
		8300: "Server RPC",
		8301: "Serf LAN",
		8302: "Serf WAN",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "consul_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasUIExposed(envs, cmds, svc.Ports) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "consul_ui_exposed",
			Message: fmt.Sprintf("service %q: Consul UI exposed on all interfaces without ACL", svc.Name),
		})
	}

	if !hasGossipEncryption(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "consul_no_gossip_encrypt",
			Message: fmt.Sprintf("service %q: Consul gossip encryption not configured", svc.Name),
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
				case "consul_ui_exposed":
					r.Summary.UIExposed++
				case "consul_no_gossip_encrypt":
					r.Summary.NoGossipEncrypt++
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

	fmt.Fprintf(&b, "  Summary: no_acl=%d no_tls=%d exposed_port=%d ui_exposed=%d no_gossip_encrypt=%d\n",
		r.Summary.NoACL, r.Summary.NoTLS, r.Summary.ExposedPort,
		r.Summary.UIExposed, r.Summary.NoGossipEncrypt)

	return b.String()
}
