package zookeeperaudit

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
	NoAuth       int `json:"no_auth"`
	NoTLS        int `json:"no_tls"`
	ExposedPort  int `json:"exposed_port"`
	FourLetterCmd int `json:"four_letter_cmd"`
	AdminServer  int `json:"admin_server"`
	NoACL        int `json:"no_acl"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

func isZookeeperImage(image string) bool {
	lower := strings.ToLower(image)
	parts := []string{
		"zookeeper", "bitnami/zookeeper", "library/zookeeper",
		"wurstmeister/zookeeper", "confluentinc/cp-zookeeper",
		"digitalwonderland/zookeeper",
	}
	for _, p := range parts {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func hasAuth(envs []string, args []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "ZOO_ENABLE_AUTH=YES") ||
			strings.Contains(upper, "ZOO_SERVER_USERS") ||
			strings.Contains(upper, "ZOOKEEPER_AUTH_PROVIDER") ||
			strings.Contains(upper, "ZK_DIGEST_AUTH") {
			return true
		}
	}
	for _, a := range args {
		if strings.Contains(a, "authProvider") || strings.Contains(a, "requireClientAuthScheme") {
			return true
		}
	}
	return false
}

func hasTLS(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "ZOO_TLS_CLIENT_AUTH") ||
			strings.Contains(upper, "ZOO_SSL_KEYSTORE") ||
			strings.Contains(upper, "ZOO_TLS_KEYSTORE") ||
			strings.Contains(upper, "SERVER_CNXN_FACTORY=NETTYSERVERCNXNFACTORY") {
			return true
		}
	}
	return false
}

func hasFourLetterCommands(envs []string, args []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "ZOO_4LW_COMMANDS_WHITELIST=*") {
			return true
		}
	}
	for _, a := range args {
		if strings.Contains(a, "4lw.commands.whitelist=*") {
			return true
		}
	}
	return false
}

func hasAdminServerEnabled(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "ZOO_ADMINSERVER_ENABLED=TRUE") ||
			strings.Contains(upper, "ADMIN.ENABLESERVER=TRUE") {
			return true
		}
	}
	return false
}

func hasACLEnabled(envs []string, args []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "SKIP_ACL=NO") ||
			strings.Contains(upper, "ZOO_SKIP_ACL=NO") {
			return true
		}
	}
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "SKIP_ACL=YES") ||
			strings.Contains(upper, "ZOO_SKIP_ACL=YES") {
			return false
		}
	}
	return hasAuth(envs, args)
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment
	args := svc.Command

	if !hasAuth(envs, args) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "zk_no_auth",
			Message: fmt.Sprintf("service %q: ZooKeeper has no authentication configured — any client can connect", svc.Name),
		})
	}

	if !hasTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "zk_no_tls",
			Message: fmt.Sprintf("service %q: ZooKeeper running without TLS — client connections are plaintext", svc.Name),
		})
	}

	for _, pm := range svc.Ports {
		port := pm.TargetPort
		if port == 2181 || port == 2888 || port == 3888 || port == 8080 {
			if pm.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "zk_exposed_port",
					Message: fmt.Sprintf("service %q: ZooKeeper port %d exposed on all interfaces", svc.Name, port),
				})
			}
		}
	}

	if hasFourLetterCommands(envs, args) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "zk_four_letter_cmd",
			Message: fmt.Sprintf("service %q: ZooKeeper has all four-letter commands enabled (potential info leak)", svc.Name),
		})
	}

	if hasAdminServerEnabled(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "zk_admin_server",
			Message: fmt.Sprintf("service %q: ZooKeeper admin server is explicitly enabled (port 8080)", svc.Name),
		})
	}

	if !hasACLEnabled(envs, args) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "zk_no_acl",
			Message: fmt.Sprintf("service %q: ZooKeeper ACL enforcement may be disabled", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isZookeeperImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "zk_no_auth":
					r.Summary.NoAuth++
				case "zk_no_tls":
					r.Summary.NoTLS++
				case "zk_exposed_port":
					r.Summary.ExposedPort++
				case "zk_four_letter_cmd":
					r.Summary.FourLetterCmd++
				case "zk_admin_server":
					r.Summary.AdminServer++
				case "zk_no_acl":
					r.Summary.NoACL++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("ZooKeeper Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No ZooKeeper services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_auth=%d no_tls=%d exposed_port=%d four_letter_cmd=%d admin_server=%d no_acl=%d\n",
		r.Summary.NoAuth, r.Summary.NoTLS, r.Summary.ExposedPort,
		r.Summary.FourLetterCmd, r.Summary.AdminServer, r.Summary.NoACL)

	return b.String()
}
