package neo4jaudit

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
	NoAuth          int `json:"no_auth"`
	NoTLS           int `json:"no_tls"`
	ExposedPort     int `json:"exposed_port"`
	DefaultPassword int `json:"default_password"`
	RemoteShell     int `json:"remote_shell"`
	BrowserExposed  int `json:"browser_exposed"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var neo4jImages = []string{
	"neo4j", "bitnami/neo4j",
}

func isNeo4jImage(image string) bool {
	img := strings.ToLower(image)
	for _, ci := range neo4jImages {
		if strings.Contains(img, ci) {
			return true
		}
	}
	return false
}

func hasAuth(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "NEO4J_AUTH=NONE") {
			return false
		}
		if strings.Contains(upper, "NEO4J_DBMS_SECURITY_AUTH__ENABLED=FALSE") ||
			strings.Contains(upper, "NEO4J_DBMS_SECURITY_AUTH_ENABLED=FALSE") {
			return false
		}
		if strings.Contains(upper, "NEO4J_AUTH=") && !strings.Contains(upper, "NEO4J_AUTH=NONE") {
			return true
		}
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "NEO4J_DBMS_SSL") ||
			strings.Contains(upper, "BOLT+S") ||
			strings.Contains(upper, "NEO4J_DBMS_CONNECTOR_BOLT_TLS_LEVEL") ||
			strings.Contains(upper, "NEO4J_DBMS_CONNECTOR_HTTPS_ENABLED=TRUE") {
			return true
		}
	}
	return false
}

func hasDefaultPassword(envs []string) bool {
	defaults := []string{"neo4j", "admin", "password", "changeme", "default", "test"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.HasPrefix(lower, "neo4j_auth=neo4j/") {
			pw := strings.TrimPrefix(lower, "neo4j_auth=neo4j/")
			for _, d := range defaults {
				if pw == d {
					return true
				}
			}
		}
		if strings.Contains(lower, "neo4j_password=") {
			for _, d := range defaults {
				if strings.HasSuffix(lower, "="+d) {
					return true
				}
			}
		}
	}
	return false
}

func hasRemoteShell(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "NEO4J_DBMS_SHELL_ENABLED=TRUE") ||
			strings.Contains(upper, "NEO4J_DBMS_SECURITY_PROCEDURES_UNRESTRICTED=*") {
			return true
		}
	}
	return false
}

func hasBrowserExposed(envs []string, ports []compose.PortMapping) bool {
	for _, p := range ports {
		if p.TargetPort == 7474 && p.IsAllInterfaces() {
			for _, e := range envs {
				upper := strings.ToUpper(e)
				if strings.Contains(upper, "NEO4J_AUTH=NONE") ||
					strings.Contains(upper, "NEO4J_DBMS_SECURITY_AUTH__ENABLED=FALSE") {
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

	if !hasAuth(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "neo4j_no_auth",
			Message: fmt.Sprintf("service %q: Neo4j authentication disabled or not configured", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "neo4j_no_tls",
			Message: fmt.Sprintf("service %q: Neo4j running without TLS encryption", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		7474: "Neo4j HTTP Browser",
		7687: "Neo4j Bolt protocol",
		7473: "Neo4j HTTPS",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "neo4j_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasDefaultPassword(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "neo4j_default_password",
			Message: fmt.Sprintf("service %q: Neo4j using default/weak password", svc.Name),
		})
	}

	if hasRemoteShell(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "neo4j_remote_shell",
			Message: fmt.Sprintf("service %q: Neo4j remote shell or unrestricted procedures enabled", svc.Name),
		})
	}

	if hasBrowserExposed(envs, svc.Ports) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "neo4j_browser_exposed",
			Message: fmt.Sprintf("service %q: Neo4j browser exposed on all interfaces without authentication", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isNeo4jImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "neo4j_no_auth":
					r.Summary.NoAuth++
				case "neo4j_no_tls":
					r.Summary.NoTLS++
				case "neo4j_exposed_port":
					r.Summary.ExposedPort++
				case "neo4j_default_password":
					r.Summary.DefaultPassword++
				case "neo4j_remote_shell":
					r.Summary.RemoteShell++
				case "neo4j_browser_exposed":
					r.Summary.BrowserExposed++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("Neo4j Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No Neo4j services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_auth=%d no_tls=%d exposed_port=%d default_password=%d remote_shell=%d browser_exposed=%d\n",
		r.Summary.NoAuth, r.Summary.NoTLS, r.Summary.ExposedPort,
		r.Summary.DefaultPassword, r.Summary.RemoteShell, r.Summary.BrowserExposed)

	return b.String()
}
