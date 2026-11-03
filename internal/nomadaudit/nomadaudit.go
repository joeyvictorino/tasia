package nomadaudit

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
	DefaultToken    int `json:"default_token"`
	RawExecEnabled  int `json:"raw_exec_enabled"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var nomadImages = []string{
	"hashicorp/nomad", "multani/nomad",
}

func isNomadImage(image string) bool {
	img := strings.ToLower(image)
	for _, ni := range nomadImages {
		if strings.Contains(img, ni) {
			return true
		}
	}
	return false
}

func hasACL(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "NOMAD_ACL_ENABLED=TRUE") {
			return true
		}
		if strings.Contains(upper, "NOMAD_ACL_ENABLED=FALSE") {
			return false
		}
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "NOMAD_TLS_") ||
			strings.Contains(upper, "NOMAD_CACERT") ||
			strings.Contains(upper, "NOMAD_CLIENT_CERT") ||
			strings.Contains(upper, "NOMAD_TLS_CERT_FILE") ||
			strings.Contains(upper, "NOMAD_TLS_KEY_FILE") {
			return true
		}
	}
	return false
}

func hasDefaultToken(envs []string) bool {
	defaults := []string{"secret", "admin", "nomad", "root", "changeme", "password", "default", "test"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "nomad_token=") ||
			strings.Contains(lower, "nomad_acl_token=") ||
			strings.Contains(lower, "nomad_management_token=") {
			for _, d := range defaults {
				if strings.HasSuffix(lower, "="+d) {
					return true
				}
			}
		}
	}
	return false
}

func hasRawExec(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "NOMAD_CLIENT_DRIVER_RAW_EXEC_ENABLED=TRUE") ||
			strings.Contains(upper, "RAW_EXEC_ENABLED=TRUE") ||
			strings.Contains(upper, "DRIVER_RAW_EXEC=TRUE") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	if !hasACL(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "nomad_no_acl",
			Message: fmt.Sprintf("service %q: Nomad ACLs not enabled", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "nomad_no_tls",
			Message: fmt.Sprintf("service %q: Nomad running without TLS encryption", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		4646: "Nomad HTTP API",
		4647: "Nomad RPC",
		4648: "Nomad Serf (gossip)",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "nomad_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasDefaultToken(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "nomad_default_token",
			Message: fmt.Sprintf("service %q: Nomad using default/weak ACL token", svc.Name),
		})
	}

	if hasRawExec(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "nomad_raw_exec",
			Message: fmt.Sprintf("service %q: Nomad raw_exec driver enabled — allows arbitrary host commands", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isNomadImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "nomad_no_acl":
					r.Summary.NoACL++
				case "nomad_no_tls":
					r.Summary.NoTLS++
				case "nomad_exposed_port":
					r.Summary.ExposedPort++
				case "nomad_default_token":
					r.Summary.DefaultToken++
				case "nomad_raw_exec":
					r.Summary.RawExecEnabled++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Nomad Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No Nomad services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_acl=%d no_tls=%d exposed_port=%d default_token=%d raw_exec=%d\n",
		r.Summary.NoACL, r.Summary.NoTLS, r.Summary.ExposedPort,
		r.Summary.DefaultToken, r.Summary.RawExecEnabled)

	return b.String()
}
