package elasticaudit

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
	TotalServices      int `json:"total_services"`
	TotalFindings      int `json:"total_findings"`
	SecurityDisabled   int `json:"security_disabled"`
	ExposedPorts       int `json:"exposed_ports"`
	DefaultCredentials int `json:"default_credentials"`
	MissingTLS         int `json:"missing_tls"`
	AnonymousAccess    int `json:"anonymous_access"`
	UnsafeConfig       int `json:"unsafe_config"`
}

var elasticImages = []string{
	"elasticsearch", "elastic/elasticsearch",
	"opensearch", "opensearchproject/opensearch",
	"bitnami/elasticsearch",
}

func isElasticImage(image string) bool {
	lower := strings.ToLower(image)
	for _, ei := range elasticImages {
		if strings.Contains(lower, ei) {
			return true
		}
	}
	return false
}

var defaultCredPairs = []string{
	"elastic:changeme", "elastic:elastic", "admin:admin",
	"admin:password", "elastic:password", "kibana:changeme",
}

func getEnvValue(envs []string, key string) string {
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], key) {
			return parts[1]
		}
	}
	return ""
}

func hasEnvContaining(envs []string, substr string) bool {
	lower := strings.ToLower(substr)
	for _, e := range envs {
		if strings.Contains(strings.ToLower(e), lower) {
			return true
		}
	}
	return false
}

func isElasticPort(port compose.PortMapping) bool {
	return port.TargetPort == 9200 || port.TargetPort == 9300
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isElasticImage(svc.Image) {
		return sr
	}

	securityDisabled := false
	secVal := getEnvValue(svc.Environment, "xpack.security.enabled")
	if secVal == "" {
		secVal = getEnvValue(svc.Environment, "XPACK_SECURITY_ENABLED")
	}
	if strings.EqualFold(secVal, "false") {
		securityDisabled = true
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "security_disabled",
			Message: fmt.Sprintf("Service '%s' has xpack.security.enabled=false; authentication and authorization are disabled", svc.Name),
		})
	}

	for _, port := range svc.Ports {
		if isElasticPort(port) && port.IsAllInterfaces() {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "exposed_port",
				Message: fmt.Sprintf("Service '%s' exposes Elasticsearch port %d on all interfaces", svc.Name, port.TargetPort),
			})
		}
	}

	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		for _, cred := range defaultCredPairs {
			if strings.Contains(lower, cred) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "critical",
					Rule:    "default_credentials",
					Message: fmt.Sprintf("Service '%s' uses default credentials in environment configuration", svc.Name),
				})
				goto doneCredCheck
			}
		}
	}
	{
		pass := getEnvValue(svc.Environment, "ELASTIC_PASSWORD")
		if pass == "" {
			pass = getEnvValue(svc.Environment, "ELASTICSEARCH_PASSWORD")
		}
		if pass != "" {
			lp := strings.ToLower(pass)
			if lp == "changeme" || lp == "password" || lp == "elastic" || lp == "admin" || lp == "secret" {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "critical",
					Rule:    "default_credentials",
					Message: fmt.Sprintf("Service '%s' uses weak/default password '%s'", svc.Name, pass),
				})
			}
		}
	}
doneCredCheck:

	hasTLS := hasEnvContaining(svc.Environment, "xpack.security.transport.ssl") ||
		hasEnvContaining(svc.Environment, "xpack.security.http.ssl") ||
		hasEnvContaining(svc.Environment, "ELASTICSEARCH_ENABLE_SECURITY") ||
		hasEnvContaining(svc.Environment, "plugins.security.ssl")

	if !hasTLS && !securityDisabled {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "missing_tls",
			Message: fmt.Sprintf("Service '%s' has no TLS/SSL configuration for Elasticsearch transport or HTTP", svc.Name),
		})
	}

	if securityDisabled {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "anonymous_access",
			Message: fmt.Sprintf("Service '%s' allows anonymous access with security disabled", svc.Name),
		})
	}

	if hasEnvContaining(svc.Environment, "discovery.type=single-node") && svc.NetworkMode == "host" {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "unsafe_config",
			Message: fmt.Sprintf("Service '%s' runs single-node Elasticsearch with host networking; cluster is directly exposed", svc.Name),
		})
	}

	for _, v := range svc.Volumes {
		lower := strings.ToLower(v)
		if strings.Contains(lower, "/etc/elasticsearch") && !strings.Contains(lower, ":ro") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "unsafe_config",
				Message: fmt.Sprintf("Service '%s' mounts Elasticsearch config directory writable", svc.Name),
			})
			break
		}
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
			case "security_disabled":
				s.SecurityDisabled++
			case "exposed_port":
				s.ExposedPorts++
			case "default_credentials":
				s.DefaultCredentials++
			case "missing_tls":
				s.MissingTLS++
			case "anonymous_access":
				s.AnonymousAccess++
			case "unsafe_config":
				s.UnsafeConfig++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Elasticsearch Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Security disabled:      %d\n", r.Summary.SecurityDisabled)
	fmt.Fprintf(&b, "  Exposed ports:          %d\n", r.Summary.ExposedPorts)
	fmt.Fprintf(&b, "  Default credentials:    %d\n", r.Summary.DefaultCredentials)
	fmt.Fprintf(&b, "  Missing TLS:            %d\n", r.Summary.MissingTLS)
	fmt.Fprintf(&b, "  Anonymous access:       %d\n", r.Summary.AnonymousAccess)
	fmt.Fprintf(&b, "  Unsafe configuration:   %d\n\n", r.Summary.UnsafeConfig)
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
