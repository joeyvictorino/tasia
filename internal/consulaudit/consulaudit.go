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
	NoACL            int `json:"no_acl"`
	NoGossipEncrypt  int `json:"no_gossip_encrypt"`
	NoTLS            int `json:"no_tls"`
	ExposedPort      int `json:"exposed_port"`
	DevMode          int `json:"dev_mode"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var consulImages = []string{
	"consul", "hashicorp/consul", "bitnami/consul",
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

func hasACL(envs []string, command []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "CONSUL_ACL_ENABLED=TRUE") ||
			strings.Contains(upper, "CONSUL_LOCAL_CONFIG") && strings.Contains(upper, "ACL") && strings.Contains(upper, "ENABLED") {
			return true
		}
	}
	for _, c := range command {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "acl") && strings.Contains(lower, "enabled") {
			return true
		}
	}
	return false
}

func hasGossipEncryption(envs []string, command []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "CONSUL_GOSSIP_ENCRYPTION_KEY") ||
			strings.Contains(upper, "GOSSIP_ENCRYPTION") ||
			strings.Contains(upper, "ENCRYPT=") {
			return true
		}
	}
	for _, c := range command {
		if strings.Contains(c, "-encrypt") {
			return true
		}
	}
	return false
}

func hasTLS(envs []string, command []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "CONSUL_TLS") ||
			strings.Contains(upper, "CONSUL_CACERT") ||
			strings.Contains(upper, "CONSUL_CLIENT_CERT") ||
			strings.Contains(upper, "CONSUL_HTTP_SSL=TRUE") ||
			strings.Contains(upper, "CONSUL_GRPC_TLS") {
			return true
		}
	}
	for _, c := range command {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "-ca-file") || strings.Contains(lower, "-cert-file") ||
			strings.Contains(lower, "tls") {
			return true
		}
	}
	return false
}

func isDevMode(envs []string, command []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "consul_dev=true") ||
			strings.Contains(lower, "consul_development=true") {
			return true
		}
	}
	for _, c := range command {
		if c == "-dev" || c == "--dev" || strings.Contains(c, "agent -dev") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	if !hasACL(envs, svc.Command) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "consul_no_acl",
			Message: fmt.Sprintf("service %q: Consul ACLs not enabled", svc.Name),
		})
	}

	if !hasGossipEncryption(envs, svc.Command) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "consul_no_gossip_encrypt",
			Message: fmt.Sprintf("service %q: Consul gossip encryption not configured", svc.Name),
		})
	}

	if !hasTLS(envs, svc.Command) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "consul_no_tls",
			Message: fmt.Sprintf("service %q: Consul running without TLS", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		8500: "Consul HTTP API",
		8501: "Consul HTTPS API",
		8600: "Consul DNS",
		8300: "Consul server RPC",
		8301: "Consul Serf LAN",
		8302: "Consul Serf WAN",
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

	if isDevMode(envs, svc.Command) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "consul_dev_mode",
			Message: fmt.Sprintf("service %q: Consul running in development mode", svc.Name),
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
				case "consul_no_gossip_encrypt":
					r.Summary.NoGossipEncrypt++
				case "consul_no_tls":
					r.Summary.NoTLS++
				case "consul_exposed_port":
					r.Summary.ExposedPort++
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

	fmt.Fprintf(&b, "  Summary: no_acl=%d no_gossip_encrypt=%d no_tls=%d exposed_port=%d dev_mode=%d\n",
		r.Summary.NoACL, r.Summary.NoGossipEncrypt, r.Summary.NoTLS,
		r.Summary.ExposedPort, r.Summary.DevMode)

	return b.String()
}
